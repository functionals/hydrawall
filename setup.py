# -*- coding: utf-8 -*-
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
"""
Created on Wed Aug 14 15:26:08 2024

@author: Ian Malloy
"""

'import lib py and lib pl'

"make all in lib py"


<<<<<<< HEAD
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
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
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
<<<<<<< HEAD
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
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
    def __init__(self, *args, **kwargs):
        self.nodist = kwargs.pop('nodist', False)
        self.nopip = kwargs.pop('nopip', False)
        self.progress = kwargs.pop('progress', None)
        self.verbose = kwargs.pop('verbose', False)
        super().__init__(*args, **kwargs)

    def post_setup(self, context):
<<<<<<< HEAD
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
=======
        os.environ['VIRTUAL_ENV'] = context.env_dir
        if not self.nodist:
            self.install_setuptools(context)
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
        if not self.nopip and not self.nodist:
            self.install_pip(context)

    def reader(self, stream, context):
<<<<<<< HEAD
<<<<<<< HEAD
=======
        """
        Read lines from a subprocess' output stream and either pass to a progress
        callable (if specified) or write progress information to sys.stderr.
        """
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
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
<<<<<<< HEAD
=======
        # Download script into the virtual environment's binaries folder
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
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
<<<<<<< HEAD
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = threading.Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
        t2 = threading.Thread(target=self.reader, args=(p.stderr, 'stderr'))
=======
        # Install in the virtual environment
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
        args = [context.env_exe, fn]
        p = Popen(args, stdout=PIPE, stderr=PIPE, cwd=binpath)
        t1 = threading.Thread(target=self.reader, args=(p.stdout, 'stdout'))
        t1.start()
<<<<<<< HEAD
        t2 = Thread(target=self.reader, args=(p.stderr, 'stderr'))
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
=======
        t2 = threading.Thread(target=self.reader, args=(p.stderr, 'stderr'))
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
        t2.start()
        p.wait()
        t1.join()
        t2.join()
        if progress is not None:
            progress('done.', 'main')
        else:
            sys.stderr.write('done.\n')
<<<<<<< HEAD
<<<<<<< HEAD
        os.unlink(distpath)

    def install_setuptools(self, context):
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
=======
        # Clean up - no longer needed
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
        os.unlink(distpath)

    def install_setuptools(self, context):
        url = "https://bootstrap.pypa.io/ez_setup.py"
        self.install_script(context, 'setuptools', url)
<<<<<<< HEAD
        # clear up the setuptools archive which gets downloaded
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
        pred = lambda o: o.startswith('setuptools-') and o.endswith('.tar.gz')
        files = filter(pred, os.listdir(context.bin_path))
        for f in files:
            f = os.path.join(context.bin_path, f)
            os.unlink(f)

    def install_pip(self, context):
<<<<<<< HEAD
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
=======
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
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

<<<<<<< HEAD
>>>>>>> ae65bf7851a214435bdc7deef25deb75dd28fb00
=======
# CustomConfig Class
class CustomConfig(BuildConfig()):
    default = 'build'
    languages = []
    out = 'out'
    preserve_paths = True
    builtins = True
>>>>>>> 08cb51a09caa321718d2eb52eb21d1d54d73e72a
