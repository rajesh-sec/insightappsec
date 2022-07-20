from setuptools import setup, find_packages
from io import open
from os import path
from sys import platform

import pathlib
# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# automatically captured required modules for install_requires in requirements.txt
with open(path.join(HERE, 'requirements.txt'), encoding='utf-8') as f:
    all_reqs = f.read().split('\n')

install_requires = [x.strip() for x in all_reqs if ('git+' not in x) and (
    not x.startswith('#')) and (not x.startswith('-'))]
dependency_links = [x.strip().replace('git+', '') for x in all_reqs \
                    if 'git+' not in x]
                    
if platform == 'win32':
  setup (
    name = 'appsec',
    description = 'A simple commandline app for InsightAppSec',
    version = '1.0.0',
    packages = find_packages(), # list of all packages
    install_requires = install_requires,
    python_requires='>=3.6', # any python greater than 3.6
    #entry_points={
     #   'console_scripts': [
     #       'appsec = lib.appsec:main',
     #   ]},
     entry_points='''
        [console_scripts]
        appsec=lib.appsec:main
    ''',
    author="Rajesh Kumar",
    keyword="Rapid7, Insightappsec, appsec, insightappsec-cli",
    long_description=README,
    long_description_content_type="text/markdown",
    license='MIT',
    url='',
    #download_url='https://github.com/CITGuru/cver/archive/1.0.0.tar.gz',
    dependency_links=dependency_links,
    author_email='',
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
    ]
  )
else:
  setup (
    name = 'appsec',
    description = 'A simple commandline app for InsightAppSec',
    version = '1.0.0',
    packages = find_packages(), # list of all packages
    install_requires = install_requires,
    python_requires='>=3.6', # any python greater than 3.6
    entry_points='''
        [console_scripts]
        appsec=lib.appsec:main
    ''',
    author="Rajesh Kumar",
    keyword="Rapid7, Insightappsec, appsec, insightappsec-cli",
    long_description=README,
    long_description_content_type="text/markdown",
    license='MIT',
    url='',
    #download_url='https://github.com/CITGuru/cver/archive/1.0.0.tar.gz',
    dependency_links=dependency_links,
    author_email='',
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
    ]
  )
