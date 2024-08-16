# -*- coding: utf-8 -*-
"""
Created on Wed Aug 14 15:26:08 2024

@author: Ian Malloy
"""
from setuptools import find_packages, setup

setup(
    name="Dshell",
    version="3.2.3",
    author="USArmyResearchLab",
    description="An extensible network forensic analysis framework",
    url="https://github.com/USArmyResearchLab/Dshell",
    python_requires='>=3.8',
    packages=find_packages(),
    package_data={
        "dshell": ["data/dshellrc", "data/GeoIP/readme.txt"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
    ],
    install_requires=[
        "geoip2",
        "pcapy-ng",
        "pypacker",
        "pyopenssl",
        "elasticsearch",
        "tabulate",
    ],
    entry_points={
        "console_scripts": [
            "dshell-decode = dshell.decode:main_command_line",
        ],
        "dshell_plugins": [],
    },
    scripts=[
        "scripts/dshell",
    ],
)


import os
import sys
import threading
from subprocess import Popen, PIPE
from urllib.request import urlretrieve
from urllib.parse import urlparse
import venv
from build import BuildConfig

# ExtendedEnvBuilder Class
class ExtendedEnvBuilder(venv.EnvBuilder):
    def __init__(self, *args, **kwargs):
        self.nodist = kwargs.pop('nodist', False)
        self.nopip = kwargs.pop('nopip', False)
        self.progress = kwargs.pop('progress', None)
        self.verbose = kwargs.pop('verbose', False)
        super().__init__(*args, **kwargs)

    def post_setup(self, context):
        os.environ['VIRTUAL_ENV'] = context.env_dir
        if not self.nodist:
            self.install_setuptools(context)
        if not self.nopip and not self.nodist:
            self.install_pip(context)

    def reader(self, stream, context):
        progress = self.progress
        while True:
            s = stream.readline()
            if not s:
                break
            if progress is not None:
                progress(s, context)
            else:
                if not self.verbose:
                    sys.stderr.write('.')
                else:
                    sys.stderr.write(s.decode('utf-8'))
                sys.stderr.flush()
        stream.close()

    def install_script(self, context, name, url):
        _, _, path, _, _, _ = urlparse(url)
        fn = os.path.split(path)[-1]
        binpath = context.bin_path
        distpath = os.path.join(binpath, fn)
        urlretrieve(url, distpath)
        progress = self.progress
        if self.verbose:
            term = '\n'
        else:
            term = ''
        if progress is not None:
            progress('Installing %s ...%s' % (name, term), 'main')
        else:
            sys.stderr.write('Installing %s ...%s' % (name, term))
            sys.stderr.flush()
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = threading.Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
        t2 = threading.Thread(target=self.reader, args=(p.stderr, 'stderr'))
        t2.start()
        p.wait()
        t1.join()
        t2.join()
        if progress is not None:
            progress('done.', 'main')
        else:
            sys.stderr.write('done.\n')
        os.unlink(distpath)

    def install_setuptools(self, context):
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
        pred = lambda o: o.startswith('setuptools-') and o.endswith('.tar.gz')
        files = filter(pred, os.listdir(context.bin_path))
        for f in files:
            f = os.path.join(context.bin_path, f)
            os.unlink(f)

    def install_pip(self, context):
        url = 'https://bootstrap.pypa.io/get-pip.py'
        self.install_script(context, 'pip', url)

# Setup Script
setup(
    name='my_package',
    version='0.1.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='A short description of the package',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/yourrepository',
    packages=find_packages(),
    install_requires=[
        'numpy',
        'requests',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'my_command=my_package.module:main_function',
        ],
    },
)

# CustomConfig Class
class CustomConfig(BuildConfig()):
    default = 'build'
    languages = []
    out = 'out'
    preserve_paths = True
    builtins = True
