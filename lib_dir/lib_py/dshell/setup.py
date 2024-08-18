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
