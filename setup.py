import ast
import os
import re

from setuptools import setup


here = os.path.abspath('.')
with open(os.path.join(here, 'README.rst'), 'rt') as f:
    README = f.read()

_version_re = re.compile(r'__version__\s*=\s*(.*)')
with open(os.path.join(here, 'BotUtils', '__init__.py'), 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(f.read().decode('utf-8')).group(1)))

install_requires = [
    'colorlog',
    'credmgr',
    'praw',
    'psycopg2_binary',
    'sentry_sdk',
]

extras = {'tunnel': ['sshtunnel'], 'sqla': ['sqlalchemy']}

setup(
    name='BotUtils',
    author='Lil_SpazJoekp',
    author_email='lilspazjoekp@gmail.com',
    description="Personal Utilities for Spaz's bots",
    license='Private',
    version=version,
    install_requires=install_requires,
    packages=['BotUtils'],
    extras_require=extras
)
