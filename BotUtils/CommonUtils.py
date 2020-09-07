import io
import logging
import logging.config
import subprocess
import sys

import praw
import psycopg2
import sentry_sdk
from credmgr import CredentialManager
from psycopg2.extras import NamedTupleCursor


log = logging.getLogger(__name__)
devMode = sys.platform == 'darwin'

class BotServices:

    def __init__(self, botName, apiToken=None):
        self.botName = botName
        self.server = None
        self.credmgr = CredentialManager(apiToken=apiToken)
        self.bot = self.credmgr.bot(botName)

    def reddit(self, redditUsername, botName=None) -> praw.Reddit:
        if botName:
            return self.credmgr.bot(botName).redditApp.reddit(redditUsername)
        else:
            return self.bot.redditApp.reddit(redditUsername)

    def _getDbConnectionSettings(self, botName=None):
        if botName:
            settings = self.credmgr.bot(botName).databaseCredential
        else:
            settings = self.bot.databaseCredential
        params = {
            'database': settings.database, 'user': settings.databaseUsername, 'password': settings.databasePassword, 'host': settings.databaseHost, 'port': settings.databasePort
        }
        if settings.useSsh:
            from sshtunnel import SSHTunnelForwarder
            if not self.server:
                if settings.userSshKey:
                    authParams = {'ssh_pkey': io.StringIO(settings.privateKey), 'ssh_private_key_password': settings.privateKeyPassphrase}
                else:
                    authParams = {'ssh_password': settings.sshPassword}
                self.server = SSHTunnelForwarder((settings.sshHost, settings.sshPort), ssh_username=settings.sshUsername, **authParams,
                    remote_bind_address=(settings.databaseHost, settings.databasePort), logger=log)
            self.server.start()
            log.debug('server connected')
            params['port'] = self.server.local_bind_port
        return params

    def postgres(self, botName=None, cursorFactory=NamedTupleCursor, maxAttempts=5) -> psycopg2.extensions.cursor:
        params = self._getDbConnectionSettings(botName)
        attempts = 0
        cursor = None
        try:
            while not cursor and attempts < maxAttempts:
                attempts += 1
                try:
                    postgres = psycopg2.connect(**params, cursor_factory=cursorFactory)
                    postgres.autocommit = True
                    return postgres.cursor()
                except Exception as error:
                    log.exception(error)
        except Exception as error:
            log.exception(error)

    def sqlalc(self, botName=None, flavor='postgresql', scoped=False, schema=None, engineKwargs=None, sessionKwargs=None, baseClass=None, createAll=False):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        params = self._getDbConnectionSettings(botName)
        url = f"{flavor}://{params['user']}:{params['password']}@{params['host']}:{params['port']}/{params['database']}"
        sessionKwargs = sessionKwargs or {}
        engineKwargs = engineKwargs or {}
        engine = create_engine(url, **engineKwargs)
        Session = sessionmaker(bind=engine, **sessionKwargs)
        session = Session()
        if scoped:
            from sqlalchemy import event
            from sqlalchemy.orm import scoped_session, mapper
            from sqlalchemy.ext.declarative import declarative_base
            DBSession = scoped_session(Session)
            baseClass = baseClass or object

            @event.listens_for(mapper, 'init')
            def auto_add(target, args, kwargs):
                for k, v in kwargs.items():
                    setattr(target, k, v)
                DBSession.merge(target)
                if not DBSession.autocommit:
                    DBSession.commit()

            class _Base(baseClass):
                query = DBSession.query_property()
                if schema:
                    __table_args__ = {'schema': schema}

                @classmethod
                def get(cls, ident):
                    return cls.query.get(ident)

            Base = declarative_base(bind=session.bind, cls=_Base)
            if createAll:
                Base.metadata.create_all()
            return Base
        else:
            return Session()

    def logger(self, botName=None):
        if botName:
            settings = self.credmgr.bot(botName).sentryToken
        else:
            settings = self.bot.sentryToken
        logColors = {'DEBUG': 'bold_cyan', 'INFO': 'bold_green', 'WARNING': 'bold_yellow', 'ERROR': 'bold_red', 'CRITICAL': 'bold_purple'}
        secondaryLogColors = {'message': {'DEBUG': 'bold_cyan', 'INFO': 'white', 'WARNING': 'bold_yellow', 'ERROR': 'bold_red', 'CRITICAL': 'bold_purple'}}
        colors = {'log_colors': logColors, 'secondary_log_colors': secondaryLogColors}
        formatter = {
            'style': '{',
            '()': 'colorlog.ColoredFormatter',
            'format': '{asctime} [{log_color}{levelname:^9}{reset}] [{cyan}{name}{reset}] [{blue}{funcName}{reset}] [{yellow}{filename}:{lineno}{reset}] {message_log_color}{message}',
            'datefmt': '%m/%d/%Y %I:%M:%S %p', **colors
        }
        try:
            import colorlog
        except ImportError:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'colorlog'])
            try:
                import colorlog
            except ImportError:
                formatter = {'format': f'%(asctime)s %(levelname)-8s [%(name)s]  - %(message)s', 'datefmt': '%m/%d/%Y %I:%M:%S %p'}
        config = {
            'version': 1, 'formatters': {'default': formatter}, 'handlers': {
                'consoleHandler': {
                    'class': 'logging.StreamHandler', 'level': ('INFO', 'DEBUG')[devMode], 'formatter': 'default', 'stream': 'ext://sys.stdout'
                }
            }, 'loggers': {botName: {'level': 'INFO', 'handlers': ['consoleHandler']}, __name__: {'level': 'DEBUG', 'handlers': ['consoleHandler']}}
        }
        environment = 'development' if devMode else 'production'
        sentry_sdk.init(dsn=settings.dsn, attach_stacktrace=True, send_default_pii=True, _experiments={'auto_enabling_integrations': True}, environment=environment)
        logging.config.dictConfig(config)
        loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
        for logger in loggers:
            if not 'sqlalchemy' in logger.name:
                if devMode:
                    logger.setLevel(logging.DEBUG)
                else:
                    logger.setLevel(logging.INFO)
        return logging.getLogger(botName)

if __name__ == '__main__':
    credmgr = CredentialManager()
    botName = 'SiouxBot'
    services = BotServices(botName)
    sql = services.postgres()
    log = services.logger()
    log.info('test')
    reddit = services.reddit('siouxsie_siouxv2')
    sql.execute('select 1')
    results = sql.fetchall()
    log.info(results)
    log.info(reddit.user.me())