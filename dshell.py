from __future__ import annotations
import logging
import struct
from pypacker import pypacker, checksum, triggerlist
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.layer567 import bgp, http, mqtt, rtp, sip, telnet, tpkt, pmap,tftp, dns, dhcp, iso15118, ntp,  radius, stun
from pypacker.structcbs import pack_Q, unpack_Q_le, pack_B, unpack_B, unpack_H, pack_ipv4_header, pack_ipv6_header, unpack_I, pack_H_le, unpack_H_le
import os
import string
import pathlib
import tempfile
import pyproject_hooks
from . import ProjectBuilder
from ._compat import importlib
from ._types import StrPath, SubprocessRunner
from .env import DefaultIsolatedEnv
import subprocess
import re
import math
import ipaddress
import collections
from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.alertout import AlertOutput
from hashlib import md5
import json
from typing import Any, Dict, cast, List, Optional, Type, Union,Callable, Sequence,TypeVar
import aiohttp
import aiohttp.http
import requests
import requests.utils
import geoip2
import geoip2.models
from geoip2.errors import (
    AddressNotFoundError,
    AuthenticationError,
    GeoIP2Error,
    HTTPError,
    InvalidRequestError,
    OutOfQueriesError,
    PermissionRequiredError,
)
from geoip2.models import City, Country, Insights
from geoip2.types import IPAddress
import dshell.core
from dshell.output.output import Output
from pypacker.layer12 import ieee80211
from collections import defaultdict
from datetime import datetime
import dshell.util
import argparse
import array
import bz2
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import _lib
import _ffi
import dshell.core
import dshell.util
from pypacker.layer4 import ssl
from pypacker.layer4 import udp
import dshell.core
import dshell.util
import dshell.core
import sys
import binascii
import hashlib
import OpenSSL
import time
try:
    import ja3.ja3
    ja3_available = True
except ModuleNotFoundError:
    ja3_available = False
from dshell.util import human_readable_filesize
import types
from pypacker.layer4 import tcp
from fcntl import ioctl
from os import read as os_read
from os import write as os_write
import threading
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker import utils
from ipaddress import IPv4Address, IPv6Address
from pypacker.layer567 import diameter
from dshell.util import printable_text
from pypacker.pypacker import Packet
from dshell.plugins import dnsplugin
import base64
import socket
import typing
import warnings
from errno import errorcode
from functools import partial, wraps
from itertools import chain, count
from sys import platform
from weakref import WeakValueDictionary
from cryptography.hazmat.primitives.asymmetric import ec
from OpenSSL._util import (
    StrOrBytesPath as _StrOrBytesPath,
)
from OpenSSL._util import (
    exception_from_error_queue as _exception_from_error_queue,
)
from OpenSSL._util import (
    make_assert as _make_assert,
)
from OpenSSL._util import (
    no_zero_allocator as _no_zero_allocator,
)
from OpenSSL._util import (
    path_bytes as _path_bytes,
)
from OpenSSL._util import (
    text_to_bytes_and_warn as _text_to_bytes_and_warn,
)
from OpenSSL.crypto import (
    FILETYPE_PEM,
    X509,
    PKey,
    X509Name,
    X509Store,
    _EllipticCurve,
    _PassphraseHelper,
    _PrivateKey,
)
from pprint import pprint
import io
from struct import Struct
from abc import ABCMeta
from geoip2.mixins import SimpleEquality
import dpkt
from distutils.version import LooseVersion
import geoip2.records
from struct import unpack
from dshell.output.netflowout import NetflowOutput
from pypacker.structcbs import unpack_BB
from pypacker.layer12 import can, arp, dtp, pppoe
import pkgutil
from pypacker.pypacker import (mac_str_to_bytes, mac_bytes_to_str,
								ip4_str_to_bytes, ip4_bytes_to_str,
								ip6_str_to_bytes, ip6_bytes_to_str)
from dshell.plugins.dnsplugin import DNSPlugin
from pypacker.layer3.ip_shared import IP_PROTO_IP6, IP_PROTO_ICMP, IP_PROTO_IGMP, IP_PROTO_TCP, \
	IP_PROTO_UDP, IP_PROTO_ESP, IP_PROTO_PIM, IP_PROTO_IPXIP, IP_PROTO_SCTP, IP_PROTO_OSPF
import errno
from socket import htons, ntohl, ntohs
from socket import timeout as socket_timeout
from collections import namedtuple
from pypacker.layer3 import esp, icmp6, igmp, ipx, ospf, pim
from urllib.parse import parse_qs
from http import cookies
from dshell.output.colorout import ColorOutput
from elasticsearch import Elasticsearch
import dshell.output.jsonout
import gzip
import zipfile
import getpass
import faulthandler
import tabulate
import functools
import calendar
import ctypes
from binasscii import hexlify
import inspect
import operator
import pkg_resources
import pcapy
from glob import glob, iglob
from importlib import import_module
import heapq
from cryptography.hazmat.primitives import serialization
import geoip2
import maxminddb
from io import IOBase
from collections import OrderedDict
import dshell.core
import geoip2.database
import geoip2.errors
import geoip2
from dshell.dshellargparse import DshellArgumentParser
from dshell.dshellgeoip import DshellGeoIP, DshellFailedGeoIP
from dshell.dshelllist import get_output_modules

