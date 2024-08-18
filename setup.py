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


# Copyright 2024 The TensorFlow Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Sets up TensorFlow Official Models."""
import datetime
import os
import sys

from setuptools import find_packages
from setuptools import setup

version = '2.17.0'
tf_version = '2.17.0'  # Major version.

project_name = 'tf-models-official'

long_description = """The TensorFlow official models are a collection of
models that use TensorFlow's high-level APIs.
They are intended to be well-maintained, tested, and kept up to date with the
latest TensorFlow API. They should also be reasonably optimized for fast
performance while still being easy to read."""

if '--project_name' in sys.argv:
  project_name_idx = sys.argv.index('--project_name')
  project_name = sys.argv[project_name_idx + 1]
  sys.argv.remove('--project_name')
  sys.argv.pop(project_name_idx)


def _get_requirements(is_nightly=False):
  """Parses requirements.txt file."""
  install_requires_tmp = []
  dependency_links_tmp = []
  if is_nightly:
    file_name = '../nightly_requirements.txt'
  else:
    file_name = '../requirements.txt'
  with open(
      os.path.join(os.path.dirname(__file__), file_name), 'r') as f:
    for line in f:
      package_name = line.strip()
      # Skip empty line or comments starting with "#".
      if not package_name or package_name[0] == '#':
        continue
      if package_name.startswith('-e '):
        dependency_links_tmp.append(package_name[3:].strip())
      else:
        install_requires_tmp.append(package_name)
  return install_requires_tmp, dependency_links_tmp

if project_name == 'tf-models-nightly':
  install_requires, dependency_links = _get_requirements(is_nightly=True)
  version_split = version.split('.')
  version_split[1] = str(int(version_split[1]) + 1)
  version = '.'.join(version_split)
  version += '.dev' + datetime.datetime.now().strftime('%Y%m%d')
  install_requires.append('tf-nightly')
  install_requires.append('tensorflow-text-nightly')
else:
  install_requires, dependency_links = _get_requirements()
  install_requires.append(f'tensorflow~={tf_version}')
  install_requires.append(f'tensorflow-text~={tf_version}')

print('install_requires: ', install_requires)
print('dependency_links: ', dependency_links)

setup(
    name=project_name,
    version=version,
    description='TensorFlow Official Models',
    long_description=long_description,
    author='Google Inc.',
    author_email='packages@tensorflow.org',
    url='https://github.com/tensorflow/models',
    license='Apache 2.0',
    packages=find_packages(exclude=[
        'research*',
        'official.pip_package*',
        'official.benchmark*',
        'official.colab*',
        'official.recommendation.ranking.data.preprocessing*',
    ]),
    exclude_package_data={
        '': ['*_test.py',],
    },
    install_requires=install_requires,
    dependency_links=dependency_links,
    python_requires='>=3.7',
)
#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='pyja3',
    version='1.1.0',
    description='Generate JA3 fingerprints from PCAPs using Python.',
    url="https://github.com/salesforce/ja3",
    author="Tommy Stallings",
    author_email="tommy.stallings2@gmail.com",
    maintainer = "John B. Althouse",
    maintainer_email = "jalthouse@salesforce.com",
    license="BSD",
    packages=find_packages(),
    install_requires=['dpkt'],
    long_description=read('README.rst'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ],
    package_data={
        'pyja3': [],
    },
    entry_points={
        'console_scripts': [
            'ja3 = ja3.ja3:main'
        ]
    },
    keywords=['ja3', 'fingerprints', 'defender', 'ssl', 'packets']
)
import sys
import os
import glob
from setuptools import setup, Extension

PACKAGE_NAME = 'pcapy-ng'

# You might want to change these to reflect your specific configuration
include_dirs = []
library_dirs = []
libraries = []

if sys.platform == 'win32':
    if os.environ.get('WPDPACK_BASE'):
        wpdpack = os.environ['WPDPACK_BASE']
        include_dirs.append(os.path.join(wpdpack, 'Include'))
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib', 'x64'))
        else:  # x86 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib'))
    else:
        # WinPcap include files
        include_dirs.append(r'c:\wpdpack\Include')
        # WinPcap library files
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib\x64')
        else:  # x86 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib')
    libraries = ['wpcap', 'packet', 'ws2_32']
else:
    libraries = ['pcap']


# end of user configurable parameters
macros = []
sources = ['pcapdumper.cc',
           'bpfobj.cc',
           'pcapobj.cc',
           'pcap_pkthdr.cc',
           'pcapy.cc'
           ]

if sys.platform == 'win32':
    sources.append(os.path.join('win32', 'dllmain.cc'))
    macros.append(('WIN32', '1'))

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name=PACKAGE_NAME,
      version="1.0.9",
      url="https://github.com/stamparm/pcapy-ng/",
      author="Miroslav Stampar",
      author_email="miroslav@sqlmap.org",
      maintainer="Miroslav Stampar",
      maintainer_email="miroslav@sqlmap.org",
      platforms=["Unix", "Windows"],
      description="Python pcap extension",
      long_description=read('README'),
      license="Apache",
      ext_modules=[Extension(
          name="pcapy",
          sources=sources,
          define_macros=macros,
          include_dirs=include_dirs,
          library_dirs=library_dirs,
          libraries=libraries)],
      #scripts=['tests/pcapytests.py', 'tests/96pings.pcap'],
      data_files=[
          (os.path.join('share', 'doc', PACKAGE_NAME), ['README', 'LICENSE', 'pcapy.html']),
          (os.path.join('share', 'doc', PACKAGE_NAME, 'tests'), glob.glob('tests/*'))]
      )

#!/usr/bin/env python

from setuptools import find_packages, setup

# Common metadata
metadata = {
    "author": "Michael Stahn",
    "author_email": "michael.stahn.42@gmail.com",
    "url": "https://gitlab.com/mike01/pypacker",
    "license": "GPLv2",
    "description": "Pypacker: The fast and simple packet creating and parsing module",
    "python_requires": ">=3.3",
    "packages": [
        "pypacker",
        "pypacker.layer12",
        "pypacker.layer3",
        "pypacker.layer4",
        "pypacker.layer567"
    ],
    "package_data": {
        "pypacker": ["oui_stripped.txt", "native/*.so"]
    },
    "classifiers": [
        "Development Status :: 6 - Mature",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    "install_requires": [],  # Uncomment if needed
}

# Setup for Dshell
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

# Setup for Pypacker
setup(
    name="pypacker",
    version="5.5",
    **metadata
)
