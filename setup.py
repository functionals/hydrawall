# -*- coding: utf-8 -*-
<<<<<<< HEAD
"""
Created on Wed Aug 14 15:26:08 2024

@author: Ian Malloy
"""

'import lib py and lib pl'

"make all in lib py"


import os
import sys
import threading
import subprocess
from subprocess import Popen, PIPE
from urllib.request import urlretrieve
from urllib.parse import urlparse
import venv
from setuptools import setup, find_packages, Extension
from build import BuildConfig

# ExtendedEnvBuilder Class
class ExtendedEnvBuilder(venv.EnvBuilder):
=======
#!/usr/bin/python3
import smart_open
import os
import os.path
from subprocess import Popen, PIPE
import sys
from threading import Thread
from urllib.parse import urlparse
from urllib.request import urlretrieve
import venv
import asyncio
import janus

def threaded(sync_q: janus.SyncQueue[int]) -> None:
    for i in range(100):
        sync_q.put(i)
    sync_q.join()


async def async_coro(async_q: janus.AsyncQueue[int]) -> None:
    for i in range(100):
        val = await async_q.get()
        assert val == i
        async_q.task_done()


async def main() -> None:
    queue: janus.Queue[int] = janus.Queue()
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, threaded, queue.sync_q)
    await async_coro(queue.async_q)
    await fut
    queue.close()
    await queue.wait_closed()


asyncio.run(main())

class build():
    def build():
        build.build()
    build.main(__name__)
    build.__init__()
    
class Config(build.Config):
  # Put your options here
  # Defaults:
  # Default task
  default = 'build'
  # Languages to build (lang/<lang>.py)
  languages = []
  # Default output directory
  out = 'out'
  # Whether to preserve output paths (src/dir/file.py -> out/dir/file.py or out/file.py)
  preserve_paths = True
  # Enable builtin tasks (build etc.)
  builtins = True



from enum import Enum
class ExtendedEnvBuilders(venv.EnvBuilder):
 def core(self, *args, **kwargs):
        self.nodist = kwargs.pop('nodist', False)
        self.nopip = kwargs.pop('nopip', False)
        self.progress = kwargs.pop('progress', None)
        self.verbose = kwargs.pop('verbose', False)
        super().__init__(*args, **kwargs)
class core():
    def core():
        context()
        interface.core
    Enum.core
    core.janus_swi
core().janus.Term()
eval(core)
        

class smart():
    def smart():
      janus.smart
      eval(smart)
    Enum.smart
    smart.janus_swi
smart.janus.Term()
    
def self():
        sys.prefix.self
        sys.exec_prefix.self
def context():
    interface.smart
    
os.environ['VIRTUAL_ENV'] = venv.env_dir
if not self.nodist:
            self.install_setuptools(context)
        # Can't install pip without setuptools
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
        # Download script into the virtual environment's binaries folder
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
        # Install in the virtual environment
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
        t2 = Thread(target=self.reader, args=(p.stderr, 'stderr'))
        t2.start()
        p.wait()
        t1.join()
        t2.join()
        if progress is not None:
            progress('done.', 'main')
        else:
            sys.stderr.write('done.\n')
        # Clean up - no longer needed
        os.unlink(distpath)

def install_setuptools(self, context):
        """
        Install setuptools in the virtual environment.

        :param context: The information for the virtual environment
                        creation request being processed.
        """
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
        # clear up the setuptools archive which gets downloaded
        pred = lambda o: o.startswith('setuptools-') and o.endswith('.tar.gz')
        files = filter(pred, os.listdir(context.bin_path))
        for f in files:
            f = os.path.join(context.bin_path, f)
            os.unlink(f)

def install_pip(self, context):
        url = 'https://bootstrap.pypa.io/get-pip.py'
        self.install_script(context, 'pip', url)


def main(args=None):
    import argparse

    parser = argparse.ArgumentParser(prog=__name__,
                                     description='Creates virtual Python '
                                                 'environments in one or '
                                                 'more target '
                                                 'directories.')
    parser.add_argument('dirs', metavar='ENV_DIR', nargs='+',
                        help='A directory in which to create the '
                             'virtual environment.')
    parser.add_argument('--no-setuptools', default=False,
                        action='store_true', dest='nodist',
                        help="Don't install setuptools or pip in the "
                             "virtual environment.")
    parser.add_argument('--no-pip', default=False,
                        action='store_true', dest='nopip',
                        help="Don't install pip in the virtual "
                             "environment.")
    parser.add_argument('--system-site-packages', default=False,
                        action='store_true', dest='system_site',
                        help='Give the virtual environment access to the '
                             'system site-packages dir.')
    if os.name == 'nt':
        use_symlinks = False
    else:
        use_symlinks = True
    parser.add_argument('--symlinks', default=use_symlinks,
                        action='store_true', dest='symlinks',
                        help='Try to use symlinks rather than copies, '
                             'when symlinks are not the default for '
                             'the platform.')
    parser.add_argument('--clear', default=False, action='store_true',
                        dest='clear', help='Delete the contents of the '
                                           'virtual environment '
                                           'directory if it already '
                                           'exists, before virtual '
                                           'environment creation.')
    parser.add_argument('--upgrade', default=False, action='store_true',
                        dest='upgrade', help='Upgrade the virtual '
                                             'environment directory to '
                                             'use this version of '
                                             'Python, assuming Python '
                                             'has been upgraded '
                                             'in-place.')
    parser.add_argument('--verbose', default=False, action='store_true',
                        dest='verbose', help='Display the output '
                                             'from the scripts which '
                                             'install setuptools and pip.')
    options = parser.parse_args(args)
    if options.upgrade and options.clear:
        raise ValueError('you cannot supply --upgrade and --clear together.')

import argparse

parser = argparse.ArgumentParser(prog=__name__,
                                 description='Creates virtual Python '
                                             'environments in one or '
                                             'more target '
                                             'directories.')
parser.add_argument('dirs', metavar='ENV_DIR', nargs='+',
                    help='A directory in which to create the '
                         'virtual environment.')
parser.add_argument('--no-setuptools', default=False,
                    action='store_true', dest='nodist',
                    help="Don't install setuptools or pip in the "
                         "virtual environment.")
parser.add_argument('--no-pip', default=False,
                    action='store_true', dest='nopip',
                    help="Don't install pip in the virtual "
                         "environment.")
parser.add_argument('--system-site-packages', default=False,
                    action='store_true', dest='system_site',
                    help='Give the virtual environment access to the '
                         'system site-packages dir.')
if os.name == 'nt':
    use_symlinks = False
else:
    use_symlinks = True
parser.add_argument('--symlinks', default=use_symlinks,
                    action='store_true', dest='symlinks',
                    help='Try to use symlinks rather than copies, '
                         'when symlinks are not the default for '
                         'the platform.')
parser.add_argument('--clear', default=False, action='store_true',
                    dest='clear', help='Delete the contents of the '
                                       'virtual environment '
                                       'directory if it already '
                                       'exists, before virtual '
                                       'environment creation.')
parser.add_argument('--upgrade', default=False, action='store_true',
                    dest='upgrade', help='Upgrade the virtual '
                                         'environment directory to '
                                         'use this version of '
                                         'Python, assuming Python '
                                         'has been upgraded '
                                         'in-place.')
parser.add_argument('--verbose', default=False, action='store_true',
                    dest='verbose', help='Display the output '
                                         'from the scripts which ')

def args():
    interface.py.args(input())
    
options = parser.parse_args(args)
if options.upgrade and options.clear:
    raise ValueError('you cannot supply --upgrade and --clear together.')


for d in options.dirs:
    build.create(d)
import os
import os.path
import venv

class ExtendedEnvBuilder(venv.EnvBuilder):
    """
    This builder installs setuptools and pip so that you can pip or
    easy_install other packages into the created virtual environment.

    :param nodist: If true, setuptools and pip are not installed into the
                   created virtual environment.
    :param nopip: If true, pip is not installed into the created
                  virtual environment.
    :param progress: If setuptools or pip are installed, the progress of the
                     installation can be monitored by passing a progress
                     callable. If specified, it is called with two
                     arguments: a string indicating some progress, and a
                     context indicating where the string is coming from.
                     The context argument can have one of three values:
                     'main', indicating that it is called from virtualize()
                     itself, and 'stdout' and 'stderr', which are obtained
                     by reading lines from the output streams of a subprocess
                     which is used to install the app.

                     If a callable is not specified, default progress
                     information is output to sys.stderr.
    """

>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
    def __init__(self, *args, **kwargs):
        self.nodist = kwargs.pop('nodist', False)
        self.nopip = kwargs.pop('nopip', False)
        self.progress = kwargs.pop('progress', None)
        self.verbose = kwargs.pop('verbose', False)
        super().__init__(*args, **kwargs)

    def post_setup(self, context):
<<<<<<< HEAD
        os.environ['VIRTUAL_ENV'] = context.env_dir
        if not self.nodist:
            self.install_setuptools(context)
=======
        """
        Set up any packages which need to be pre-installed into the
        virtual environment being created.

        :param context: The information for the virtual environment
                        creation request being processed.
        """
        os.environ['VIRTUAL_ENV'] = context.env_dir
        if not self.nodist:
            self.install_setuptools(context)
        # Can't install pip without setuptools
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
        if not self.nopip and not self.nodist:
            self.install_pip(context)

    def reader(self, stream, context):
<<<<<<< HEAD
=======
        """
        Read lines from a subprocess' output stream and either pass to a progress
        callable (if specified) or write progress information to sys.stderr.
        """
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
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
<<<<<<< HEAD
=======
        # Download script into the virtual environment's binaries folder
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
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
<<<<<<< HEAD
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = threading.Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
        t2 = threading.Thread(target=self.reader, args=(p.stderr, 'stderr'))
=======
        # Install in the virtual environment
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
        t2 = Thread(target=self.reader, args=(p.stderr, 'stderr'))
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
        t2.start()
        p.wait()
        t1.join()
        t2.join()
        if progress is not None:
            progress('done.', 'main')
        else:
            sys.stderr.write('done.\n')
<<<<<<< HEAD
        os.unlink(distpath)

    def install_setuptools(self, context):
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
=======
        # Clean up - no longer needed
        os.unlink(distpath)

    def install_setuptools(self, context):
        """
        Install setuptools in the virtual environment.

        :param context: The information for the virtual environment
                        creation request being processed.
        """
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
        # clear up the setuptools archive which gets downloaded
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
        pred = lambda o: o.startswith('setuptools-') and o.endswith('.tar.gz')
        files = filter(pred, os.listdir(context.bin_path))
        for f in files:
            f = os.path.join(context.bin_path, f)
            os.unlink(f)

    def install_pip(self, context):
<<<<<<< HEAD
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
=======
        """
        Install pip in the virtual environment.

        :param context: The information for the virtual environment
                        creation request being processed.
        """
        url = 'https://bootstrap.pypa.io/get-pip.py'
        self.install_script(context, 'pip', url)

builder = ExtendedEnvBuilder(system_site_packages=options.system_site,
                               clear=options.clear,
                               symlinks=options.symlinks,
                               upgrade=options.upgrade,
                               nodist=options.nodist,
                               nopip=options.nopip,
                               verbose=options.verbose)


def parse(args=None):
    import argparse

    parser = argparse.ArgumentParser(prog=__name__,
                                     description='Creates virtual Python '
                                                 'environments in one or '
                                                 'more target '
                                                 'directories.')
    parser.add_argument('dirs', metavar='ENV_DIR', nargs='+',
                        help='A directory in which to create the '
                             'virtual environment.')
    parser.add_argument('--no-setuptools', default=False,
                        action='store_true', dest='nodist',
                        help="Don't install setuptools or pip in the "
                             "virtual environment.")
    parser.add_argument('--no-pip', default=False,
                        action='store_true', dest='nopip',
                        help="Don't install pip in the virtual "
                             "environment.")
    parser.add_argument('--system-site-packages', default=False,
                        action='store_true', dest='system_site',
                        help='Give the virtual environment access to the '
                             'system site-packages dir.')
    if os.name == 'nt':
        use_symlinks = False
    else:
        use_symlinks = True
    parser.add_argument('--symlinks', default=use_symlinks,
                        action='store_true', dest='symlinks',
                        help='Try to use symlinks rather than copies, '
                             'when symlinks are not the default for '
                             'the platform.')
    parser.add_argument('--clear', default=False, action='store_true',
                        dest='clear', help='Delete the contents of the '
                                           'virtual environment '
                                           'directory if it already '
                                           'exists, before virtual '
                                           'environment creation.')
    parser.add_argument('--upgrade', default=False, action='store_true',
                        dest='upgrade', help='Upgrade the virtual '
                                             'environment directory to '
                                             'use this version of '
                                             'Python, assuming Python '
                                             'has been upgraded '
                                             'in-place.')
    parser.add_argument('--verbose', default=False, action='store_true',
                        dest='verbose', help='Display the output '
                                             'from the scripts which '
                                             'install setuptools and pip.')
    options = parser.parse_args(args)
    if options.upgrade and options.clear:
        raise ValueError('you cannot supply --upgrade and --clear together.')
    builder = ExtendedEnvBuilder(system_site_packages=options.system_site,
                                   clear=options.clear,
                                   symlinks=options.symlinks,
                                   upgrade=options.upgrade,
                                   nodist=options.nodist,
                                   nopip=options.nopip,
                                   verbose=options.verbose)
    for d in options.dirs:
        builder.create(d)

if __name__ == '__main__':
    rc = 1
    try:
        main()
        rc = 0
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
    sys.exit(rc)
    builder = ExtendedEnvBuilder(system_site_packages=options.system_site,
                                   clear=options.clear,
                                   symlinks=options.symlinks,
                                   upgrade=options.upgrade,
                                   nodist=options.nodist,
                                   nopip=options.nopip,
                                   verbose=options.verbose)
    for d in options.dirs:
        builder.create(d)

if __name__ == '__main__':
    rc = 1
    try:
        main()
        rc = 0
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
    sys.exit(rc)

'''python -m venv /path/to/new/virtual/environment standard tool for creating virtual environments'''
def create(self, env_dir):
    """
    Create a virtualized Python environment in a directory.
    env_dir is the target directory to create an environment in.
    """
    env_dir = os.path.abspath(env_dir)
    context = self.ensure_directories(env_dir)
    self.create_configuration(context)
    self.setup_python(context)
    self.setup_scripts(context)
    self.post_setup(context)
    
    
def interface():
        if __name__ == "__main__":
            import sys
            interface(str(sys.argv[1]))
import sys
core().smart()
def interface_engine(self):
        self.data = []
kind = smart_open.k # class variable shared by all instances
k = 0
try:
   for line in iter(sys.stdin.readline, b''):
      k = k + 1
      print(line)
except KeyboardInterrupt:
   sys.stdout.flush()
   pass
print(k)

import dshell


smart.dshell
dshell.__init__.py
dshell.janus.smart
janus.smart
eval()
def start(): 
        eval(start)
start.enum.Enum()

       

        
[build.system]
requires = ["pdm-backend"]
build.backend == "pdm.backend"



[build]
build.main(__name__). blib
# Or remove the class above and put your options here




>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
