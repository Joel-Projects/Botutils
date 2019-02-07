import os, json, sys, psycopg2, io, paramiko, base64, asyncio, logging
from sshtunnel import SSHTunnelForwarder
from psycopg2 import pool, extras
# import raven
log = None

# def getBotSettings(botName: str, serviceName: str, path='../', secretsFileName='secrets.json'):
def getBotSettings(botName: str, serviceName: str, path=os.path.dirname(os.path.realpath(__file__)), secretsFileName='secrets.json'):
    '''Returns Bot settings from '[path]\\secrets.json' in tuple format.

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`
        serviceName : str
            Name of the service as defined in 'secrets.json'
            e.g.: `reddit`, `discord`, `postgres`
        path : str, optional
            Path of to the secrets.json file
            e.g.: '/home/user/bot/'
            Default: __file__ dir path
        path : str, optional
            Name of the bot as defined in 'secrets.json'

        Returns
        -------
        json
            values from servce
    '''

    settings = {}
    if not path == '':
        if path[-1:] in ['/', '\\']:
            fileName = path + secretsFileName
        else:
            if sys.platform == 'win32':
                fileName = path + '\\' + secretsFileName
            else:
                fileName = path + '/' + secretsFileName
    else:
        fileName = secretsFileName
    try:
        if not os.path.exists(fileName):
            raise IOError
        with open(fileName) as file:
            settings = json.load(file)[botName][serviceName]
        try:
            file.close()
        except:
            pass
    except IOError:
        pass
    except:
        pass
    return settings

def getReddit(botName: str, refreshToken: str = None, auth = False):
    '''Returns a Reddit Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`

        Returns
        -------
        Reddit
    '''
    import praw
    settings = getBotSettings(botName, 'reddit')
    if refreshToken and not auth:
        return praw.Reddit(client_id=settings['client_id'], client_secret=settings['client_secret'], refresh_token=refreshToken, user_agent=settings['user_agent'], redirect_uri=settings['redirect_uri'])
    elif auth:
        return praw.Reddit(client_id=settings['client_id'], client_secret=settings['client_secret'], user_agent=settings['user_agent'], redirect_uri=settings['redirect_uri'])
    else:
        return praw.Reddit(client_id=settings['client_id'], client_secret=settings['client_secret'], refresh_token=settings['refresh_token'], user_agent=settings['user_agent'], redirect_uri=settings['redirect_uri'])

def getRedditCrypto(botName: str, redditUsername: str, remote=False):
    '''Returns a Reddit Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`

        Returns
        -------
        Reddit
    '''
    crypto = TokenCrypto2(botName)
    refreshToken = crypto.getRefreshToken(redditUsername)
    import praw
    settings = getBotSettings(botName, 'reddit')
    return praw.Reddit(**settings, refresh_token=refreshToken)

def getRedditCryptoAsync(botName: str, redditUsername: str, loop=None):
    '''Returns a Reddit Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`

        Returns
        -------
        Reddit
    '''
    crypto = TokenCrypto2(botName)
    refreshToken = crypto.getRefreshToken(redditUsername)
    import asyncpraw as praw
    settings = getBotSettings(botName, 'reddit')
    if 'refresh_token' in settings:
        settings.pop('refresh_token')
    return praw.Reddit(**settings, refresh_token=refreshToken, loop=loop or asyncio.get_event_loop())

def getDiscordClient(botName:str, prefix, removeHelpCmd=True, **kwargs):
    '''Returns a Discord Bot Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`
        prefix : str or list or tuple
            Bot command prefix.
        removeHelpCmd: bool, optional
            Default: True
        **kwargs: any, optional
            Passes additional kwargs to the discord.ext.commands.bot.Bot instance

        Returns
        -------
        (discord.ext.commands.bot.Bot, token: str)
    '''
    import discord
    from discord.ext.commands import Bot
    settings = getBotSettings(botName, 'discord')
    token = settings['token']

    if isinstance(prefix, str): prefix = [prefix]
    client: Bot = Bot(command_prefix=prefix, **kwargs)


    if removeHelpCmd: client.remove_command('help')

    return client, token

def getPostgres(botName: str, remote=sys.platform == 'darwin', connectionPool=False):
    '''Returns a psycopg2 Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`

        Returns
        -------
        SQL Cursor
    '''
    settings = getBotSettings(botName, 'postgres')
    params = {'database': settings['dbName'], 'user': settings['dbUser'], 'password': settings['dbPass'], 'host': settings['dbHost']}

    try:
        if not remote and not connectionPool:
            postgres = psycopg2.connect(**params)
            postgres.autocommit = True
            cursor: psycopg2.extensions.cursor = postgres.cursor()
            return cursor
        elif not remote and connectionPool:
            postgres: psycopg2.pool.ThreadedConnectionPool = psycopg2.pool.ThreadedConnectionPool(1, 1000, **params)
            return postgres
        elif remote:
            settings = getBotSettings(botName, 'postgresRemote')
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(settings['pkeyString']))
            server = SSHTunnelForwarder((settings['sshHost'], 22), ssh_username='bot', ssh_pkey=pkey, remote_bind_address=('localhost', 5432))
            server.start()
            logStuff("server connected", logging.INFO)
            params = {'database': settings['dbName'], 'user': settings['dbUser'], 'password': settings['dbPass'], 'host': settings['dbHost'], 'port': server.local_bind_port}
            if not connectionPool:
                postgres = psycopg2.connect(**params)
                postgres.autocommit = True
                cursor: psycopg2.extensions.cursor = postgres.cursor()
                logStuff('database connected', logging.INFO)
                return cursor
            elif connectionPool:
                postgres: psycopg2.pool.ThreadedConnectionPool = psycopg2.pool.ThreadedConnectionPool(1, 1000, **params)
                return postgres
    except Exception as error:
        logStuff(f'Error connecting to DB: {error}', logging.ERROR)
        return

def getAsyncPostgres(botName: str, loop=None, remote=False, connectionPool=False):
    '''Returns a psycopg2 Instance

        Parameters
        ----------
        botName : str
            Name of the bot as defined in :`'secrets.json'`

        Returns
        -------
        SQL Cursor
    '''
    settings = getBotSettings(botName, 'postgres')
    params = {'database': settings['dbName'], 'user': settings['dbUser'], 'password': settings['dbPass'], 'host': settings['dbHost']}

    try:
        loop = loop or asyncio.get_event_loop()
        import asyncpg
        if remote:
            import paramiko
            from sshtunnel import SSHTunnelForwarder
            settings = getBotSettings(botName, 'postgresRemote')
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(settings['pkeyString']))
            server = SSHTunnelForwarder((settings['sshHost'], 22), ssh_username='bot', ssh_pkey=pkey, remote_bind_address=('localhost', 5432))
            server.start()
            logStuff("server connected", logging.INFO)
            params = {'database': settings['dbName'], 'user': settings['dbUser'], 'password': settings['dbPass'], 'host': settings['dbHost'], 'port': server.local_bind_port}
            pool = loop.run_until_complete(asyncpg.create_pool(**params))
            # postgres = psycopg2.connect(**params)
            # postgres.autocommit = True
            # cursor: psycopg2.extensions.cursor = postgres.cursor()
            logStuff('database connected', logging.INFO)
            return pool
        else:
            postgres = psycopg2.connect(**params)
            postgres.autocommit = True
            cursor: psycopg2.extensions.cursor = postgres.cursor()
            return cursor
    except Exception as error:
        logStuff(f'Error connecting to DB: {error}', logging.ERROR)
        return


def getApps(path=os.path.dirname(os.path.realpath(__file__)), secretsFileName='redditapps.json'):
    settings = {}
    if not path == '':
        if path[-1:] in ['/', '\\']:
            fileName = path + secretsFileName
        else:
            if sys.platform == 'win32':
                fileName = path + '\\' + secretsFileName
            else:
                fileName = path + '/' + secretsFileName
    else:
        fileName = secretsFileName
    if not os.path.exists(fileName):
        raise IOError
    with open(fileName) as file:
        settings = json.load(file)
    try:
        file.close()
    except:
        pass
    return settings

def getRedditApps(): return getApps()

class TokenCrypto:

    def __init__(self, botName: str, sql: psycopg2.extensions.cursor):
        self.botName = botName
        self.sql = sql

    def decrypt(self, encrypted: bytes):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['privateKey']).decrypt(encrypted)

    def encrypt(self, string: str):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['publicKey']).encrypt(string.encode('utf-8'), 'g')[0]

    def getRefreshToken(self, redditor: str):
        sql = self.sql
        client_id = getBotSettings(self.botName, 'reddit')['client_id']
        sql.execute("SELECT * FROM refreshtokens WHERE redditor=%s AND clientid=%s AND revoked=false", (redditor, client_id))
        results = sql.fetchall()
        if len(results) >= 1:
            result = results[0]
            encryptedToken = base64.b64decode(bytes(result[0]))
            try:
                decryptedToken = self.decrypt(encryptedToken).decode()
            except Exception as error:
                logStuff(error, logging.ERROR)
            return decryptedToken

class TokenCrypto2:

    def __init__(self, botName: str):
        self.botName = botName
        self.sql = getPostgres('personalBot', sys.platform == 'darwin')
        
    def decrypt(self, encrypted: bytes):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['privateKey']).decrypt(encrypted)

    def encrypt(self, string: str):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['publicKey']).encrypt(string.encode('utf-8'), 'g')[0]

    def getRefreshToken(self, redditor: str):
        sql = self.sql
        client_id = getBotSettings(self.botName, 'reddit')['client_id']
        sql.execute("SELECT * FROM refreshtokens WHERE redditor=%s AND clientid=%s AND revoked=false", (redditor, client_id))
        results = sql.fetchall()
        if len(results) >= 1:
            result = results[0]
            encryptedToken = base64.b64decode(bytes(result[0]))
            try:
                decryptedToken = self.decrypt(encryptedToken).decode()
            except Exception as error:
                logStuff(error, logging.ERROR)
            return decryptedToken

def parseSql(self, results):
    results = [(key.get('key'), json.loads(key.get('value'))) for key in [result for result in results]]
    if len(results) > 0: return results
    else: return None

class TokenCryptoAsync:

    def __init__(self, botName: str, loop=None):
        self.botName = botName
        self.loop = loop
        self.sql = getAsyncPostgres('personalBot', self.loop, sys.platform == 'darwin')
        
    def decrypt(self, encrypted: bytes):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['privateKey']).decrypt(encrypted)

    def encrypt(self, string: str):
        from Crypto.PublicKey import RSA
        return RSA.importKey(getBotSettings('flask', 'encryptionKey')['publicKey']).encrypt(string.encode('utf-8'), 'g')[0]

    def getRefreshToken(self, redditor: str):
        sql = self.sql
        client_id = getBotSettings(self.botName, 'reddit')['client_id']
        results = parseSql(self.loop.run_until_complete(sql.fetch("SELECT * FROM refreshtokens WHERE redditor=$1 AND clientid=$2 AND revoked=false", redditor, client_id)))
        
        if len(results) >= 1:
            result = results[0]
            encryptedToken = base64.b64decode(bytes(result[0]))
            try:
                decryptedToken = self.decrypt(encryptedToken).decode()
            except Exception as error:
                logStuff(error, logging.ERROR)
            return decryptedToken

def genAuthUrl(botName, scopes: list):
    try:
        state = getBotSettings(botName, 'reddit')['state']
        reddit = getReddit(botName, auth=True)
        if scopes == ['all']:
            scopes = [key for key in reddit.get('api/v1/scopes').keys()]
        return reddit.auth.url(scopes, state)
    except Exception as error:
        raise error

class LoggerConfig(object):
    def __init__(self, botName, __version__='0.0.0'):

        configfilepath = os.path.join(os.path.dirname(__file__), 'loggingConfig.json')
        self.config = json.load(open(configfilepath, 'rt'))
        __dsn__ = getBotSettings(botName, 'sentry')['DSN']
        # Replaces the filename with one specific to each bot
        try: self.config['handlers']['rotateFileHandler']['filename'] = "_DefaultName_Logs.log".replace('_DefaultName', botName)
        except Exception: raise AttributeError('Unable to set normal logging configuration location')

        try: self.config['handlers']['rotateFileHandler_debug']['filename'] = "_DefaultName_Logs_Debug.log".replace('_DefaultName', botName)
        except Exception: raise AttributeError('Unable to set debug logging configuration location')

        # Replace the Sentry DSN ID with the app specific one
        try: self.config['handlers']['SentryHandler']['dsn'] = __dsn__
        except Exception: raise AttributeError('Unable to set Sentry DSN info')

        # Set the App Version / Release Version
        self.config['handlers']['SentryHandler']['release'] = __version__
        
        global log
        if sys.platform == 'darwin':
            log = logging.getLogger('root')
            log.setLevel(logging.DEBUG)
        else:
            log = logging.getLogger('root')


    def get_config(self):
        return self.config

def logStuff(message: str, level=30):
    global log
    if log:
        if level in logging._levelToName:
            log.log(level, message)
        else:
            print(message)
    else:
        print(message)

if __name__ == "__main__":
    reddit = getRedditCrypto('personalBot', 'Lil_SpazJoekp')
    print(reddit.user.me())