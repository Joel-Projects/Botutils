import io
import logging
import logging.config
import subprocess
import sys
from typing import List, Tuple

import praw
import psycopg2
import sentry_sdk
from credmgr import CredentialManager
from psycopg2.extras import NamedTupleCursor

log = logging.getLogger(__name__)
dev_mode = sys.platform == "darwin"


class BotServices:
    def __init__(self, bot_name, api_token=None):
        self.bot_name = bot_name
        self.server = None
        self.credmgr = CredentialManager(apiToken=api_token)
        self.bot = self.credmgr.bot(bot_name)

    def reddit(
        self, username, bot_name=None, asyncpraw=False, reddit_class=None
    ) -> praw.Reddit:
        """Provides an authenciated reddit instance.

        :param username: Redditor to authenciate as.
        :param bot_name: Specify another bot to use.
        :param asyncpraw: Whether to use asyncpraw.
        :param reddit_class: An alternate reddit class. If this is specfied `asyncpraw` will be ignored.
        :return: A Reddit instance.
        """
        if not reddit_class:
            if asyncpraw:
                import asyncpraw

                reddit_class = asyncpraw.Reddit
            else:
                reddit_class = praw.Reddit
        if bot_name:
            return self.credmgr.bot(bot_name).redditApp.reddit(
                username, reddit_class=reddit_class
            )
        else:
            return self.bot.redditApp.reddit(username, reddit_class=reddit_class)

    def _getDbConnectionSettings(self, bot_name=None):
        if bot_name:
            settings = self.credmgr.bot(bot_name).databaseCredential
        else:
            settings = self.bot.databaseCredential
        params = {
            "database": settings.database,
            "user": settings.databaseUsername,
            "password": settings.databasePassword,
            "host": settings.databaseHost,
            "port": settings.databasePort,
        }
        if settings.useSsh:
            from sshtunnel import SSHTunnelForwarder

            if not self.server:
                if settings.userSshKey:
                    authParams = {
                        "ssh_pkey": io.StringIO(settings.privateKey),
                        "ssh_private_key_password": settings.privateKeyPassphrase,
                    }
                else:
                    authParams = {"ssh_password": settings.sshPassword}
                self.server = SSHTunnelForwarder(
                    (settings.sshHost, settings.sshPort),
                    ssh_username=settings.sshUsername,
                    **authParams,
                    remote_bind_address=(settings.databaseHost, settings.databasePort),
                    logger=log,
                )
            self.server.start()
            log.debug("server connected")
            params["port"] = self.server.local_bind_port
        return params

    def postgres(
        self, bot_name=None, cursor_factory=NamedTupleCursor, max_attempts=5
    ) -> psycopg2.extensions.cursor:
        params = self._getDbConnectionSettings(bot_name)
        attempts = 0
        cursor = None
        try:
            while not cursor and attempts < max_attempts:
                attempts += 1
                try:
                    postgres = psycopg2.connect(**params, cursor_factory=cursor_factory)
                    postgres.autocommit = True
                    return postgres.cursor()
                except Exception as error:
                    log.exception(error)
        except Exception as error:
            log.exception(error)

    def sqlalc(
        self,
        bot_name=None,
        flavor="postgresql",
        scoped=False,
        schema=None,
        engine_kwargs=None,
        session_kwargs=None,
        base_class=None,
        create_all=False,
    ):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        params = self._getDbConnectionSettings(bot_name)
        url = f"{flavor}://{params['user']}:{params['password']}@{params['host']}:{params['port']}/{params['database']}"
        session_kwargs = session_kwargs or {}
        engine_kwargs = engine_kwargs or {}
        engine = create_engine(url, **engine_kwargs)
        Session = sessionmaker(bind=engine, **session_kwargs)
        session = Session()
        if scoped:
            from sqlalchemy import event
            from sqlalchemy.ext.declarative import declarative_base
            from sqlalchemy.orm import mapper, scoped_session

            DBSession = scoped_session(Session)
            base_class = base_class or object

            @event.listens_for(mapper, "init")
            def auto_add(target, args, kwargs):
                for k, v in kwargs.items():
                    setattr(target, k, v)
                DBSession.merge(target)
                if not DBSession.autocommit:
                    DBSession.commit()

            class _Base(base_class):
                query = DBSession.query_property()
                if schema:
                    __table_args__ = {"schema": schema}

                @classmethod
                def get(cls, ident):
                    return cls.query.get(ident)

            Base = declarative_base(bind=session.bind, cls=_Base)
            if create_all:
                Base.metadata.create_all()
            return Base
        else:
            return Session()

    def logger(self, bot_name=None, enable_loggers: List[Tuple[str, str]] = None):
        """Provides a logging instance.

        :param bot_name: Specify a differnt bot name than what is set in the services instance.
        :param enable_loggers: A list of tuples of packages and logging level names, e.g., `[("discord", "INFO")]`
        :return:
        :rtype:
        """
        if not enable_loggers:
            enable_loggers = []
        try:
            if bot_name:
                settings = self.credmgr.bot(bot_name).sentryToken
            else:
                settings = self.bot.sentryToken
        except Exception:
            settings = None
        log_colors = {
            "DEBUG": "bold_cyan",
            "INFO": "bold_green",
            "WARNING": "bold_yellow",
            "ERROR": "bold_red",
            "CRITICAL": "bold_purple",
        }
        secondary_log_colors = {
            "message": {
                "DEBUG": "bold_cyan",
                "INFO": "white",
                "WARNING": "bold_yellow",
                "ERROR": "bold_red",
                "CRITICAL": "bold_purple",
            }
        }
        colors = {
            "log_colors": log_colors,
            "secondary_log_colors": secondary_log_colors,
        }
        formatter = {
            "style": "{",
            "()": "colorlog.ColoredFormatter",
            "format": "{asctime} [{log_color}{levelname:^9}{reset}] [{cyan}{name}{reset}] [{blue}{funcName}{reset}] [{yellow}{filename}:{lineno}{reset}] {message_log_color}{message}{reset}",
            "datefmt": "%m/%d/%Y %I:%M:%S %p",
            **colors,
        }
        try:
            import colorlog
        except ImportError:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "colorlog"]
                )
                import colorlog
            except Exception:
                formatter = {
                    "format": f"%(asctime)s %(levelname)-8s [%(name)s]  - %(message)s",
                    "datefmt": "%m/%d/%Y %I:%M:%S %p",
                }
        config = {
            "disable_existing_loggers": False,
            "version": 1,
            "formatters": {"default": formatter},
            "handlers": {
                "consoleHandler": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                bot_name: {"level": "INFO", "handlers": ["consoleHandler"]},
                __name__: {
                    "level": "DEBUG",
                    "handlers": ["consoleHandler"],
                },
                **{
                    logger_name: {
                        "level": level.upper(),
                        "handlers": ["consoleHandler"],
                    }
                    for logger_name, level in enable_loggers
                },
            },
        }
        if not dev_mode and settings:
            sentry_sdk.init(
                dsn=settings.dsn,
                attach_stacktrace=True,
                send_default_pii=True,
                _experiments={"auto_enabling_integrations": True},
                environment="production",
            )
        logging.config.dictConfig(config)
        return logging.getLogger(bot_name)


if __name__ == "__main__":
    credmgr = CredentialManager()
    name = "SiouxBot"
    services = BotServices(name)
    sql = services.postgres()
    log = services.logger()
    log.info("test")
    reddit = services.reddit("siouxsie_siouxv2")
    sql.execute("select 1")
    results = sql.fetchall()
    log.info(results)
    log.info(reddit.user.me())
