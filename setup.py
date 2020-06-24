from setuptools import setup
import os
import re
import ast


here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.rst'), 'rt') as f:
    README = f.read()

os.chdir(here)

_version_re = re.compile(r'__version__\s*=\s*(.*)')
with open(os.path.join(here, 'BotUtils/', '__init__.py'), 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

install_requires = [
    'colorlog',
    'credmgr',
    'praw',
    'psycopg2_binary',
    'sentry_sdk',
]

extras = {'sshTunnel': ['sshtunnel']}

setup(
    name='BotUtils',
    author='Lil_SpazJoekp,test',
    author_email='lilspazjoekp@gmail.com,spaz@jesassn.org',
    description="Personal Utilities for Spaz's bots",
    license='Private',
    version=version,
    install_requires=install_requires,
    extras_require={'tunnel': ['sshtunnel']}
)
