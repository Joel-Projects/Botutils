import os

from setuptools import setup


here = os.path.abspath('.')
with open(os.path.join(here, 'README.rst'), 'rt') as f:
    README = f.read()

version = '2.0.3'

install_requires = [
    'colorlog',
    'credmgr',
    'praw',
    'psycopg2_binary',
    'sentry_sdk'
]

extras = {'sshTunnel': ['sshtunnel']}

setup(
    name='BotUtils',
    author='Lil_SpazJoekp',
    author_email='lilspazjoekp@gmail.com',
    description="Personal Utilities for Spaz's bots",
    license='Private',
    version=version,
    install_requires=install_requires,
    extras_require={'tunnel': ['sshtunnel']}
)
