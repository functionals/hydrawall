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

####################################################################
#
#
#           DSHELL A THROUGH D SCRIPTS START
#
#
###################################################################


class AlertOutput(Output):
    """
    A class that provides a default format for printing a single-line alert.
    """
    _DESCRIPTION = "Default format for printing a single-line alert"
    _DEFAULT_FORMAT = (
        "[%(plugin)s] %(ts)s %(sip)16s:%(sport)-5s %(dir_arrow)s %(dip)16s:%(dport)-5s ** %(data)s **\n"
    )


"""
ATA over Ethernet
See http://brantleycoilecompany.com/AoEr11.pdf and
https://en.wikipedia.org/wiki/ATA_over_Ethernet
"""



class AOECFG(pypacker.Packet):
    __hdr__ = (
        ("bufcnt", "H", 0),
        ("fwver", "H", 0),
        ("scnt", "B", 0),
        ("aoeccmd", "B", 0),
        ("cslen", "H", 0),
    )

ATA_DEVICE_IDENTIFY = 0xEC

class AOEATA(pypacker.Packet):
    __hdr__ = (
        ("aflags", "B", 0),
        ("errfeat", "B", 0),
        ("scnt", "B", 0),
        ("cmdstat", "B", ATA_DEVICE_IDENTIFY),
        ("lba0", "B", 0),
        ("lba1", "B", 0),
        ("lba2", "B", 0),
        ("lba3", "B", 0),
        ("lba4", "B", 0),
        ("lba5", "B", 0),
        ("res", "H", 0)
    )

class AOE(pypacker.Packet):
    __hdr__ = (
        ("ver_fl", "B", 0x10),
        ("err", "B", 0),
        ("maj", "H", 0),
        ("min", "B", 0),
        ("cmd", "B", 0),
        ("tag", "I", 0)
    )

    @property
    def ver(self) -> int:
        return self.ver_fl >> 4

    @ver.setter
    def ver(self, value: int) -> None:
        self.ver_fl = (value << 4) | (self.ver_fl & 0xF)

    @property
    def fl(self) -> int:
        return self.ver_fl & 0xF

    @fl.setter
    def fl(self, value: int) -> None:
        self.ver_fl = (self.ver_fl & 0xF0) | value


"""
Dshell3 Python API
"""


logger = logging.getLogger(__name__)

def get_plugin_information() -> dict:
    """
    Generates and returns a dictionary of plugins.

    :return: Dictionary containing plugin name -> plugin module.
    :raises ImportError: If a plugin could not be imported.
    """
    plugin_map = get_plugins()
    plugins = {}
    for name, module_path in sorted(plugin_map.items(), key=operator.itemgetter(1)):
        try:
            module = import_module(module_path)
            if hasattr(module, 'DshellPlugin'):
                plugins[name] = module.DshellPlugin()
        except Exception as e:
            raise ImportError(f"Could not load {repr(module_path)} with error: {e}")

    return plugins




"""
Address Resolution Protocol (ARP)
"""
class Hexlify:
    def __init__(self, data: bytes):
        self.data = data

    def reverse_bytes(self) -> bytes:
        """Reverse the order of bytes."""
        return bytes(reversed(self.data))

    def reverse_bytes_to_str(self) -> str:
        """Reverse the order of bytes and return a hexadecimal string representation."""
        reversed_bytes = self.reverse_bytes()
        return str.upper(hexlify(reversed_bytes).decode())

# Example usage:
# data = b'\x01\x02\x03\x04'
# hexlify_instance = Hexlify(data)
# print(hexlify_instance.reverse_bytes_to_str())  # Outputs: '04030201'




# Set properties to access flags




# Define a class to handle flag masks
class FlagMasks:
    def __init__(self, masks: Dict[str, Tuple[int, int]]):
        self.masks = masks
        self.flags = 0

    def get_property(self, name: str) -> int:
        mask, offset = self.masks.get(name, (0, 0))
        return (self.flags & mask) >> offset

    def set_property(self, name: str, value: int):
        mask, offset = self.masks.get(name, (0, 0))
        self.flags = (self.flags & ~mask) | (value << offset)

# Define the flag masks
_MASKS = {
    "whitening": (0x0100, 8),
    "sigvalid": (0x0200, 9),
    "noisevalid": (0x0400, 10),
    "decrypted": (0x0800, 11),
    "refaavalid": (0x1000, 12),
    "aaoffensesvalid": (0x2000, 13),
    "chanalias": (0x4000, 14),
    "crcchecked": (0x0004, 2),
    "crcvalid": (0x0008, 3),
    "micchecked": (0x0010, 4),
    "micvalid": (0x0020, 5),
}

class BTLE(pypacker.Packet):
    __hdr__ = (
        ("access_addr", "4s", b"\xff" * 4),
        ("info", "B", 0),
        ("len", "B", 0),
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.flags_handler = FlagMasks(_MASKS)

    def _dissect(self, buf: bytes) -> Tuple[int, int, bytes]:
        hlen = 6
        btle_type = ((buf[4] & 0x03) + 1) << 8 if buf[:4] != b"\xd6\xbe\x89\x8e" else buf[4] & 0x0F
        self._crc = buf[-3:]
        return hlen, btle_type, buf[hlen: -3]

    def bin(self, update_auto_fields=True) -> bytes:
        """Custom bin(): handle crc for BTLE."""
        return super().bin(update_auto_fields) + self.crc

    def __len__(self) -> int:
        return super().__len__() + len(self.crc)

    crc = pypacker.get_ondemand_property("crc", lambda: b"")

    def is_crc_ok(self, crc_init=0xAAAAAA) -> bool:
        return crc_btle_check(self.bin()[:-3], self.crc, crc_init)


"""
The core Dshell library

This library contains the base level plugins that all others will inherit.

PacketPlugin contains attributes and functions for plugins that work with
individual packets.

ConnectionPlugin inherits from PacketPlugin and includes additional functions
for handling reassembled connections.

It also contains class definitions used by the plugins, including definitions
for Blob, Connection, and Packet.

"""

# standard Python imports

logger = logging.getLogger(__name__)

__version__ = "3.2.3"

class SequenceNumberError(Exception):
    """Raised when reassembling connections and data is missing or overlapping."""
    pass

class DataError(Exception):
    """Raised when any data being handled is incorrect."""
    pass

# Create GeoIP reference object
try:
    geoip = DshellGeoIP()
except FileNotFoundError:
    logger.warning("GeoIP data files not found! Country and ASN lookups disabled. Check README for instructions.")
    geoip = DshellFailedGeoIP()

def print_handler_exception(e, plugin, handler):
    """Display an error message when a handler raises an exception."""
    etype = e.__class__.__name__
    logger.error(f"The {handler} for the {plugin.name!r} plugin raised an exception! ({etype}: {e})")
    logger.debug(e, exc_info=True)


class defragpkt:
    def __init__(self, length, pkt, timestamp, frame):
        self.__len__ = length
        self.pkt = pkt
        self.ts = timestamp
        self.frame = frame


# Dummy classes to represent packet layers. Replace with actual implementations or imports.
class IP:
    def __init__(self):
        self.src_s = None
        self.dst_s = None
        self.src = None
        self.dst = None
        self.p = None
        self.len = None
        self.header_len = None
        self.dlen = None

class IP6(IP):
    pass

class UDP:
    def __init__(self):
        self.sport = None
        self.dport = None

class TCP:
    def __init__(self):
        self.sport = None
        self.dport = None
        self.seq = None
        self.ack = None
        self.flags = None

class ethernet:
    class Ethernet:
        def __init__(self):
            self.src_s = None
            self.dst_s = None

class ieee80211:
    class IEEE80211:
        def __init__(self):
            self.src_s = None
            self.dst_s = None
            self.subtype = None
            self.beacon = None
            self.disassoc = None
            self.auth = None
            self.deauth = None
            self.action = None

class geoip:
    @staticmethod
    def geoip_location_lookup(ip):
        return None, None, None

    @staticmethod
    def geoip_asn_lookup(ip):
        return None

class packet:
    def __init__(self, pktlen, packet, timestamp: int, frame=0):
        self.length = pktlen
        self.packet = packet
        self.ts = timestamp
        self.frame = frame
        self.rawpkt = packet.raw_data if hasattr(packet, 'raw_data') else None

        # TODO: Use full variable names.
        self.dt = datetime.datetime.fromtimestamp(timestamp)
        self.pkt = packet
        self.pktlen = pktlen  # TODO: Is this needed?

        self.sip = None
        self.dip = None
        self.sport = None
        self.dport = None
        self.smac = None
        self.dmac = None
        self.sipcc = None
        self.dipcc = None
        self.siplat = None
        self.diplat = None
        self.siplon = None
        self.diplon = None
        self.sipasn = None
        self.dipasn = None
        self.protocol = None
        self.protocol_num = None
        self.sequence_number = None
        self.ack_number = None
        self.tcp_flags = None

        # attribute cache
        self._byte_count = None
        self._data = None

        # these are the layers Dshell will help parse
        # try to find them in the packet and eventually pull out useful data
        ethernet_p = None
        ieee80211_p = None
        ip_p = None
        tcp_p = None
        udp_p = None
        highest_layer = None

        for layer in packet:
            highest_layer = layer
            if ethernet_p is None and isinstance(layer, ethernet.Ethernet):
                ethernet_p = layer
            elif ieee80211_p is None and isinstance(layer, ieee80211.IEEE80211):
                ieee80211_p = layer
            elif ip_p is None and isinstance(layer, (IP, IP6)):
                ip_p = layer
                try:
                    if ip_p.flags & 0x1 and ip_p.offset > 0:
                        # IP fragmentation, break all further layer processing
                        break
                except AttributeError:
                    # IPv6 does not always have flags header field set
                    pass
            elif tcp_p is None and isinstance(layer, TCP):
                tcp_p = layer
            elif udp_p is None and isinstance(layer, UDP):
                udp_p = layer

        self._highest_layer = highest_layer
        self._ethernet_layer = ethernet_p     # type: ethernet.Ethernet
        self._ieee80211_layer = ieee80211_p   # type: ieee80211.IEEE80211
        self._ip_layer = ip_p                 # type: Union[IP, IP6]
        self._tcp_layer = tcp_p               # type: TCP
        self._udp_layer = udp_p               # type: UDP

        # attempt to grab MAC addresses
        if ethernet_p:
            # from Ethernet
            self.smac = ethernet_p.src_s
            self.dmac = ethernet_p.dst_s
        elif ieee80211_p:
            # from 802.11
            try:
                if ieee80211_p.subtype == ieee80211.M_BEACON:
                    ieee80211_p2 = ieee80211_p.beacon
                elif ieee80211_p.subtype == ieee80211.M_DISASSOC:
                    ieee80211_p2 = ieee80211_p.disassoc
                elif ieee80211_p.subtype == ieee80211.M_AUTH:
                    ieee80211_p2 = ieee80211_p.auth
                elif ieee80211_p.subtype == ieee80211.M_DEAUTH:
                    ieee80211_p2 = ieee80211_p.deauth
                elif ieee80211_p.subtype == ieee80211.M_ACTION:
                    ieee80211_p2 = ieee80211_p.action
                else:
                    # can't figure out how pypacker stores the other subtypes
                    raise AttributeError
                self.smac = ieee80211_p2.src_s
                self.dmac = ieee80211_p2.dst_s
            except AttributeError:
                pass

        # process IP addresses and associated metadata (if applicable)
        if ip_p:
            # get IP addresses
            self.sip = ip_p.src_s
            self.dip = ip_p.dst_s
            self.sip_bytes = ip_p.src
            self.dip_bytes = ip_p.dst

            # get protocols, country codes, and ASNs
            self.protocol_num = ip_p.p if isinstance(ip_p, IP) else ip_p.nxt
            self.protocol = self.IP_PROTOCOL_MAP.get(self.protocol_num, str(self.protocol_num))
            self.sipcc, self.siplat, self.siplon = geoip.geoip_location_lookup(self.sip)
            self.sipasn = geoip.geoip_asn_lookup(self.sip)
            self.dipcc, self.diplat, self.diplon = geoip.geoip_location_lookup(self.dip)
            self.dipasn = geoip.geoip_asn_lookup(self.dip)

        if tcp_p:
            self.sport = tcp_p.sport
            self.dport = tcp_p.dport
            self.sequence_number = tcp_p.seq
            self.ack_number = tcp_p.ack
            self.tcp_flags = tcp_p.flags
        elif udp_p:
            self.sport = udp_p.sport
            self.dport = udp_p.dport

    @property
    def addr(self):
        """
        A standard representation of the address:
        ((self.sip, self.sport), (self.dip, self.dport))
        or
        ((self.smac, self.sport), (self.dmac, self.dport))
        """
        # try using IP addresses first
        if self.sip or self.dip:
            return (self.sip, self.sport), (self.dip, self.dport)
        # then try MAC addresses
        elif self.smac or self.dmac:
            return (self.smac, self.sport), (self.dmac, self.dport)
        # if all else fails, return Nones
        else:
            return (None, None), (None, None)

    @property
    def byte_count(self) -> int:
        """
        Total number of payload bytes in the packet.
        """
        if self._byte_count is None:
            self._byte_count = len(self.data)
        return self._byte_count

    @property
    def packet_tuple(self):
        """
        A standard representation of the raw packet tuple:
        (self.pktlen, self.rawpkt, self.ts)
        """
        return self.pktlen, self.rawpkt, self.ts

    @property
    def rawpkt(self):
        """
        The raw data that represents the full packet.
        """
        return self.pkt.bin()

@property
def data(self):
    """
    Retrieve data bytes from TCP/UDP data layer. Backtracks to data from highest layer.
    """
    if self._data is None:
        # NOTE: Using cached layers because pypacker's __getitem__ is slow.
        best_layer = self._tcp_layer or self._udp_layer or self._highest_layer

        # Pypacker doesn't handle Ethernet trailers correctly, so we need to
        # do some header calculation in order to determine the true body_bytes size.
        ip_layer = self._ip_layer
        tcp_layer = self._tcp_layer
        if ip_layer and tcp_layer:
            if isinstance(ip_layer, IP):  # IPv4
                data_size = ip_layer.len - (ip_layer.header_len + tcp_layer.header_len)
                self._data = best_layer.body_bytes[:data_size]
            else:  # IPv6
                # TODO handle
                pass

    return self._data
    


logger = logging.getLogger(__name__)




# Create GeoIP reference object
try:
    geoip = DshellGeoIP()
except FileNotFoundError:
    logging.warning("GeoIP data files not found! Country and ASN lookups disabled. Check README for instructions.")
    geoip = DshellFailedGeoIP()

# Define the Value class to handle shared state
class SharedValue:
    def __init__(self, *args, **kwargs):
        self._value = Value(*args, **kwargs)
    
    @property
    def value(self):
        return self._value.value
    
    @value.setter
    def value(self, val):
        with self._value.get_lock():
            self._value.value = val

# Define the HeapQueue class to interact with heapq
class HeapQueue:
    def __init__(self):
        self._queue = []

    def push(self, item):
        heapq.heappush(self._queue, item)

    def pop(self):
        return heapq.heappop(self._queue)

    def __bool__(self):
        return bool(self._queue)

    def __len__(self):
        return len(self._queue)

class PacketPlugin:
    """
    Base class for plugins handling individual packets.
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', __name__)
        self.description = kwargs.get('description', '')
        self.longdescription = kwargs.get('longdescription', self.description)
        self.bpf = kwargs.get('bpf', '')
        self.compiled_bpf = kwargs.get('compiled_bpf', None)
        self.vlan_bpf = kwargs.get('vlan_bpf', True)
        self.author = kwargs.get('author', '')
        self.logger = logging.getLogger(self.__class__.__name__)
        self.seen_packet_count = SharedValue('i', 0)
        self.handled_packet_count = SharedValue('i', 0)
        self.optiondict = kwargs.get('optiondict', {})
        self._packet_queue = []
        self.out = kwargs.get('output', Output())
        self.link_layer_type = 1  # Assume Ethernet
        self.defrag_ip = True
        self.current_pcap_file = None
        self._packet_fragments = defaultdict(dict)

    def produce_packets(self) -> Iterable["Packet"]:
        """Yield packets from the queue."""
        while self._packet_queue:
            yield self._packet_queue.pop(0)

    def flush(self):
        """Trigger final processing of any remaining packets."""
        pass

    def purge(self):
        """Clear caches in preparation for the next file."""
        self._packet_queue.clear()
        self._packet_fragments.clear()

    def write(self, *args, **kwargs):
        """Send information to the output formatter with additional fields."""
        kwargs.setdefault('plugin', self.name)
        kwargs.setdefault('pcapfile', self.current_pcap_file)
        self.out.write(*args, **kwargs)

    def log(self, msg, level=logging.INFO):
        """Log a message at the specified level."""
        self.logger.log(level, msg)

    def __str__(self):
        return f"<Plugin: {self.name}>"

    def __repr__(self):
        options = ','.join(f'{x}={self.optiondict.get(x)}' for x in self.optiondict)
        return f'<Plugin: {self.name}/{self.bpf}/{options}>'

    def recompile_bpf(self):
        """Compile the BPF filter."""
        if not self.bpf:
            self.logger.debug(f"Cannot compile BPF: .bpf attribute not set for plugin {self.name!r}.")
            self.compiled_bpf = None
            return

        bpf = f"({self.bpf}) or (vlan and {self.bpf})" if self.vlan_bpf else self.bpf
        self.logger.debug(f"Compiling BPF as {bpf!r}")

        try:
            self.compiled_bpf = pcapy.compile(self.link_layer_type, 65536, bpf, True, 0xffffffff)
        except pcapy.PcapError as e:
            if "no VLAN support for data link type" in str(e):
                self.logger.error(f"Cannot use VLAN filters for {self.name!r}. Consider using --no-vlan argument.")
            elif str(e) == "syntax error":
                raise ValueError(f"Fatal error compiling BPF: {bpf!r}")
            else:
                raise e

    def ipdefrag(self, packet: 'Packet') -> 'Packet':
        """Reassemble fragmented IP packets."""
        pkt = packet.pkt
        ipp = pkt.upper_layer
        if isinstance(ipp, ip.IP):
            f = self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
            f[ipp.offset] = packet

            if not ipp.flags & 0x1:
                if len(f) <= 1 and 0 in f:
                    del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                    return f[0]
                elif 0 not in f:
                    self.logger.debug(f"Missing first fragment ({packet.sip} -> {packet.dip}: {ipp.id}:{ipp.flags}:{ipp.offset})")
                    del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                    return None
                fkeys = sorted(f.keys())
                data = b''.join(f[key].pkt.upper_layer.body_bytes for key in fkeys)
                newip = ip.IP(f[fkeys[0]].pkt.upper_layer.header_bytes + data)
                newip.bin(update_auto_fields=True)
                firstpacket = f[fkeys[0]]
                del self._packet_fragments[(ipp.src, ipp.dst, ipp.id)]
                return Packet(firstpacket.pkt.__len__, firstpacket.pkt, firstpacket.ts, firstpacket.frame)

        elif isinstance(pkt, ip6.IP6):
            # TODO: Handle IPv6 fragmentation
            return pkt

    def handle_plugin_options(self):
        """Placeholder for actions after plugin args are processed."""
        pass

    def _premodule(self):
        """Prepare for capture or file processing."""
        self.premodule()
        self.out.setup()
        self.logger.debug(str(self.__dict__))

    def premodule(self):
        """Placeholder for actions before capture or file processing."""
        pass

    def _postmodule(self):
        """Finalize after capture ends."""
        self.postmodule()
        self.out.close()
        self.logger.info(f"{self.seen_packet_count.value} seen packets, {self.handled_packet_count.value} handled packets")

    def postmodule(self):
        """Placeholder for actions after capture ends."""
        pass

    def _prefile(self, infile=None):
        """Prepare for processing an individual file."""
        self.current_pcap_file = infile
        self.prefile(infile)
        self.logger.info(f'Working on file "{infile}"')

    def prefile(self, infile=None):
        """Placeholder for actions before processing an individual file."""
        pass

    def _postfile(self):
        """Finalize after processing an individual file."""
        self.postfile()

    def postfile(self):
        """Placeholder for actions after processing an individual file."""
        pass

    def filter(self, packet) -> bool:
        """Determine if a packet should be accepted or filtered out."""
        return bool(self.compiled_bpf and self.compiled_bpf.filter(packet.rawpkt))

    def consume_packet(self, packet: "Packet"):
        """Filter, defragment, and handle packets."""
        if not self.filter(packet):
            return

        with self.seen_packet_count.get_lock():
            self.seen_packet_count.value += 1

        if self.defrag_ip and isinstance(packet.pkt.upper_layer, (ip.IP, ip6.IP6)):
            defragpkt = self.ipdefrag(packet)
            if not defragpkt:
                return
            packet = defragpkt

        # Call packet_handler and process its output
        try:
            packet_handler_out = self.packet_handler(packet)
        except Exception as e:
            print_handler_exception(e, self, 'packet_handler')
            return

        failed_msg = (
            f"The output from {self.name} packet_handler must be of type dshell.Packet or a list of "
            f"such objects! Handling connections or chaining from this plugin may not be possible."
        )

        if isinstance(packet_handler_out, (list, tuple)):
            for phout in packet_handler_out:
                if isinstance(phout, Packet):
                    self._packet_queue.append(phout)
                    with self.handled_packet_count.get_lock():
                        self.handled_packet_count.value += 1
                elif phout:
                    self.logger.warning



class Connection(object):
    """
    Class for holding data about connections

    def __init__(self, plugin, first_packet)

    Args:
        first_packet:   the first Packet object to initialize connection

    Attributes:
        addr:       .addr attribute of first packet
        sip:        source IP
        smac:       source MAC address
        sport:      source port
        sipcc:      country code of source IP
        siplat:     latitude of source IP
        siplon:     longitude of source IP
        sipasn:     ASN of source IP
        clientip:   same as sip
        clientmac:  same as smac
        clientport: same as sport
        clientcc:   same as sipcc
        clientlat:  same as siplat
        clientlon:  same as siplon
        clientasn:  same as sipasn
        dip:        dest IP
        dmac:       dest MAC address
        dport:      dest port
        dipcc:      country code of dest IP
        diplat:     latitude of dest IP
        diplon:     longitude of dest IP
        dipasn:     ASN of dest IP
        serverip:   same as dip
        servermac:  same as dmac
        serverport: same as dport
        servercc:   same as dipcc
        serverlat:  same as diplat
        serverlon:  same as diplon
        serverasn:  same as dipasn
        protocol:   text version of protocol in layer-3 header
        protocol_num:   numeric version of protocol in layer-3 header
        clientpackets:  counts of packets from client side
        clientbytes:    total bytes transferred from client side
        serverpackets:  counts of packets from server side
        serverbytes:    total bytes transferred from server side
        ts:         timestamp of first packet
        dt:         datetime of first packet
        starttime:  datetime of first packet
        endtime:    datetime of last packet
        client_state:   the TCP state on the client side ("init",
                        "established", "closed", etc.)
        server_state:   the TCP state on server side
        blobs:      list of reassembled half-stream Blobs
        stop:       if True, stop following connection
        handled:    used to indicate if a connection was already passed through
                    a plugin's connection_handler function. Resets when new
                    data for a connection comes in.

    """

    # status
    # NOTE: Using strings instead of int enum to stay backwards compatible.
    INIT = "init"
    ESTABLISHED = "established"
    FINISHING = "finishing"
    CLOSED = "closed"

    def __init__(self, first_packet):
        """
        Initializes Connection object

        Args:
            first_packet:   the first Packet object to initialize connection
        """
        self.addr = first_packet.addr
        # TODO: Rename these variables to something more verbose like "source_ip"
        #   I keep getting confused whether the "s" stands for "source" or "server".
        self.sip = first_packet.sip
        self.smac = first_packet.smac
        self.sport = first_packet.sport
        self.sipcc = first_packet.sipcc
        self.siplat = first_packet.siplat
        self.siplon = first_packet.siplon
        self.sipasn = first_packet.sipasn
        self.clientip = first_packet.sip
        self.clientmac = first_packet.smac
        self.clientport = first_packet.sport
        self.clientcc = first_packet.sipcc
        self.clientlat = first_packet.siplat
        self.clientlon = first_packet.siplon
        self.clientasn = first_packet.sipasn
        self.dip = first_packet.dip
        self.dmac = first_packet.dmac
        self.dport = first_packet.dport
        self.dipcc = first_packet.dipcc
        self.diplat = first_packet.diplat
        self.diplon = first_packet.diplon
        self.dipasn = first_packet.dipasn
        self.serverip = first_packet.dip
        self.servermac = first_packet.dmac
        self.serverport = first_packet.dport
        self.servercc = first_packet.dipcc
        self.serverlat = first_packet.diplat
        self.serverlon = first_packet.diplon
        self.serverasn = first_packet.dipasn
        self.protocol = first_packet.protocol
        self.protocol_num = first_packet.protocol_num
        self.ts = first_packet.ts
        self.dt = first_packet.dt
        self.starttime = first_packet.dt
        self.endtime = first_packet.dt
        self.client_state = None
        self.server_state = None
        # self.blobs = []
        self.packets = []  # keeps track of packets in connection.
        self.stop = False
        self.handled = False

        # Cache of created blobs
        self._blob_cache = []

        self.add_packet(first_packet)

    @property
    def duration(self):
        """
        Total seconds from start_time to end_time.
        """
        tdelta = self.endtime - self.starttime
        return tdelta.total_seconds()

    @property
    def closed(self):
        return self.client_state == self.CLOSED and self.server_state == self.CLOSED

    @property
    def established(self):
        return self.client_state == self.ESTABLISHED and self.server_state == self.ESTABLISHED

    @property
    def blobs(self) -> Iterable["Blob"]:
        """
        Iterates the blobs (or messages) contained in this tcp connection

        This is dynamically generated on-demand based on the current set of packets in the connection.
        """
        if self._blob_cache:
            yield from self._blob_cache

        else:
            blobs = []

            for packet in self.packets:
                # TODO: skipping packets without data greatly improves speed, but we may want to
                #   allow them if we support using ack numbers.
                if not packet.data:
                    continue

                # If we see a sequence for an old blob, this is a retransmission.
                # Find the blob and add this packet.
                # NOTE: There is probably more to it than this, but this seems to work for now.
                seq = packet.sequence_number
                if seq is not None:
                    found = False
                    for blob in blobs:
                        if blob.sip == packet.sip and seq in blob.sequence_range:
                            blob.add_packet(packet)
                            found = True
                            break
                    if found:
                        continue

                # Create a new message if the first or the other direction has started sending data.
                if not blobs or (packet.sip != blobs[-1].sip and packet.data):
                    blobs.append(Blob(self, packet))

                # Otherwise add packet to last blob.
                else:
                    blobs[-1].add_packet(packet)

            self._blob_cache = blobs
            yield from blobs

    def add_packet(self, packet: Packet):
        """
        Adds packet to connection.

        :param packet: a Packet object to add to the connection
        """
        if packet.sip not in (self.sip, self.dip):
            raise ValueError(f"Address {repr(packet.sip)} is not part of connection.")

        self.packets.append(packet)
        # A new packet means we might need to recalculate all of the blobs
        self._blob_cache = []

        # Adjust state if packet is part of a startup or shutdown.
        if packet.tcp_flags is not None:
            # Acknowledging a completed handshake to open connection.
            if packet.tcp_flags == (tcp.TH_SYN | tcp.TH_ACK):
                self.server_state = self.ESTABLISHED
                self.client_state = self.ESTABLISHED

            # Asking to close connection.
            elif packet.tcp_flags & (tcp.TH_FIN | tcp.TH_RST):
                if packet.sip == self.serverip:
                    self.server_state = self.FINISHING
                else:
                    self.client_state = self.FINISHING

            # Closing connection acknowledged.
            elif packet.tcp_flags & tcp.TH_ACK:
                if packet.dip == self.serverip and self.server_state == self.FINISHING:
                    self.server_state = self.CLOSED
                elif packet.dip == self.clientip and self.client_state == self.FINISHING:
                    self.client_state = self.CLOSED

        if packet.dt > self.endtime:
            self.endtime = packet.dt

    def info(self):
        """
        Provides a dictionary with information about a connection. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*conn.info())

        Returns:
            Dictionary with information
        """
        d = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

        cb, cp, sb, sp = self.bytes_and_counts()

        d['duration'] = self.duration
#        d['clientbytes'] = self.clientbytes
#        d['clientpackets'] = self.clientpackets
#        d['serverbytes'] = self.serverbytes
#        d['serverpackets'] = self.serverpackets
        d['clientbytes'] = cb
        d['clientpackets'] = cp
        d['serverbytes'] = sb
        d['serverpackets'] = sp
        del d['stop']
        del d['handled']
        del d['packets']
        return d

    def _client_packets(self) -> Iterable[Packet]:
        for packet in self.packets:
            if packet.addr == self.addr:
                yield packet

    def _server_packets(self) -> Iterable[Packet]:
        for packet in self.packets:
            if packet.addr != self.addr:
                yield packet

    def bytes_and_counts(self) -> Tuple[int, int, int, int]:
        """
        Convenience function to get client and server packet and byte counts
        while only iterating over the packet list once.
        Returns a tuple of:
            (client bytes, client packets, server bytes, server packets)
        """
        cbytes, cpkts, sbytes, spkts = 0, 0, 0, 0
        for packet in self.packets:
            if packet.addr == self.addr:
                # client
                cbytes += packet.byte_count
                cpkts += bool(packet.byte_count) # only count packets with data
            else:
                # server
                sbytes += packet.byte_count
                spkts += bool(packet.byte_count) # only count packets with data
        return (cbytes, cpkts, sbytes, spkts)

    @property
    def totalbytes(self) -> int:
        """
        The total number of bytes from both directions
        """
        return sum(packet.byte_count for packet in self.packets)

    @property
    def clientbytes(self) -> int:
        """
        The total number of bytes from the client.
        """
        return sum(packet.byte_count for packet in self._client_packets())

    @property
    def clientpackets(self) -> int:
        """
        The total number of packets from the client.
        """
        # (Only counting packets with data.)
        return sum(bool(packet.byte_count) for packet in self._client_packets())

    @property
    def serverbytes(self) -> int:
        """
        The total number of bytes from the server.
        """
        return sum(packet.byte_count for packet in self._server_packets())

    @property
    def serverpackets(self) -> int:
        """
        The total number of packets from the server.
        """
        # (Only counting packets with data.)
        return sum(bool(packet.byte_count) for packet in self._server_packets())

    def __repr__(self):
        cb, cp, sb, sp = self.bytes_and_counts()
        return '%s  %16s -> %16s  (%s -> %s)  %6s  %6s %5d  %5d  %7d  %7d  %-.4fs' % (
            self.starttime,
            self.clientip,
            self.serverip,
            self.clientcc,
            self.servercc,
            self.clientport,
            self.serverport,
#            self.clientpackets,
#            self.serverpackets,
#            self.clientbytes,
#            self.serverbytes,
            cp,
            sp,
            cb,
            sb,
            self.duration,
        )


# TODO: Rename this "TCPBlob" and then have a more generic "Blob" class it inherits from.
class Blob(object):
    """
    Class for holding and reassembling pieces of a connection.

    A Blob holds the packets and reassembled data for traffic moving in one
    direction in a connection, before direction changes.

    def __init__(self, first_packet, direction)

    Args:
        connection:     The Connection object that this Blob comes from. (Used for validating packets.)
        first_packet:   the first Packet object to initialize Blob

    Attributes:
        addr:       .addr attribute of the first packet
        ts:         timestamp of the first packet
        starttime:  datetime for first packet
        endtime:    datetime of last packet
        sip:        source IP
        smac:       source MAC address
        sport:      source port
        sipcc:      country code of source IP
        sipasn:     ASN of source IP
        dip:        dest IP
        dmac:       dest MAC address
        dport:      dest port
        dipcc:      country code of dest IP
        dipasn:     ASN of dest IP
        protocol:   text version of protocol in layer-3 header
        direction:  direction of the blob -
                    'cs' for client-to-server, 'sc' for server-to-client
        ack_sequence_numbers: set of ACK numbers from the receiver for ####################################
                              collected data packets
        packets:    list of all packets in the blob
        hidden (bool):  Used to indicate that a Blob should not be passed to
                    next plugin. Can theoretically be overruled in, say, a
                    connection_handler to force a Blob to be passed to next
                    plugin.
    """

    # max offset before wrap, default is MAXINT32 for TCP sequence numbers
    MAX_OFFSET = 0xffffffff

    CLIENT_TO_SERVER = 'cs'
    SERVER_TO_CLIENT = 'sc'

    def __init__(self, connection: Connection, first_packet):
        self.connection = connection
        self.addr = first_packet.addr
        self.ts = first_packet.ts
        self.starttime = first_packet.ts
        self.endtime = first_packet.ts
        self.sip = first_packet.sip
        self.smac = first_packet.smac
        self.sport = first_packet.sport
        self.sipcc = first_packet.sipcc
        self.sipasn = first_packet.sipasn
        self.dip = first_packet.dip
        self.dmac = first_packet.dmac
        self.dport = first_packet.dport
        self.dipcc = first_packet.dipcc
        self.dipasn = first_packet.dipasn
        self.protocol = first_packet.protocol
        #        self.ack_sequence_numbers = {}
        self.packets = []
        #        self.data_packets = []
        self.__data_bytes = b''

        # Used for data caching
        self._data = None
        self._segments = None

        # Maps sequence number with packets
        self._seq_map = {}
        self.seq_max = 0
        self.seq_min = 0

        # Used to indicate that a Blob should not be passed to next plugin.
        # Can theoretically be overruled in, say, a connection_handler to
        # force a Blob to be passed to next plugin.
        self.hidden = False

        if self.sip == self.connection.clientip and \
                (not self.sport or self.sport == self.connection.clientport):
            # packet moving from client to server
            self.direction = self.CLIENT_TO_SERVER
        else:
            # packet moving from server to client
            self.direction = self.SERVER_TO_CLIENT

        self.add_packet(first_packet)

    @property
    def all_packets(self):
        warnings.warn("all_packets has been replaced with packets attribute", DeprecationWarning)
        return self.packets

#    @property
#    def starttime(self):
#        return min(packet.dt for packet in self.packets)

    @property
    def start_time(self):
        return self.starttime

#    @property
#    def endtime(self):
#        return max(packet.dt for packet in self.packets)

    @property
    def end_time(self):
        return self.endtime

    @property
    def frames(self) -> List[int]:
        """
        The frame identifiers for the packets which contain the message.
        """
        return [packet.frame for packet in self.packets]

    def get_packets(self, start, end=None) -> List["Packet"]:
        """
        Returns the packets that contain data for the given start offset up to the end offset.
        If end offset is not provided, just the packet containing the start offset is provided.
        """
        packets = []

        # TODO: Double check logic on this.

        # If not a TCP connection, return frames that had data.
        if self.packets[0].tcp_flags is None:
            offset = 0
            for packet in self.packets:
                if not packet.data:
                    continue

                offset += len(packet.data)
                if offset > start:
                    packets.append(packet)
                    if end is None or offset >= end:
                        break

        # Otherwise, base offsets on sequence numbers.
        else:
            initial_seq = None
            for seq, packet in self.segments:
                if initial_seq is None:
                    initial_seq = seq
                offset = seq - initial_seq
                end_offset = offset + len(packet.data)
                if end_offset > start:
                    packets.append(packet)
                    if end is None or end_offset >= end:
                        break

        return packets

    def get_frames(self, start, end=None) -> List[int]:
        """
        Returns frame identifiers for the packets that contain data for the given start offset
        up to the end offset.
        If end offset is not provided, just the frame identifier for the packet containing the
        start offset is provided.
        """
        return [packet.frame for packet in self.get_packets(start, end=end)]

    @property
    def sequence_numbers(self) -> List[int]:
        """
        The starting sequence numbers found within the packets.
        """
        return list(self._seq_map.keys())

    @property
    def sequence_range(self) -> range:
        """
        The range of sequence numbers found within the packets.
        """
#        sequence_numbers = self.sequence_numbers
#        if not sequence_numbers:
#            return range(0, 0)
#
#        min_seq = min(sequence_numbers)
#        max_seq = max(sequence_numbers)
#        return range(min_seq, max_seq + len(self._seq_map[max_seq].data))
        if not self._seq_map:
            return range(0, 0)

        return range(self.seq_min, self.seq_max + len(self._seq_map[self.seq_max].data))

    @property
    def segments(self) -> List[Tuple[int, "Packet"]]:
        """
        List of valid (sequence number, packet) tuples in order by sequence number.
        """
        if self._segments is not None:
            return self._segments

        segments = []
        # Iterate through segments, ignoring segments that cause overlap in data.
        expected_seq = None
        prev_packet = None
        for seq, packet in sorted(self._seq_map.items()):
            if expected_seq is None:
                expected_seq = seq

            # If the sequence is greater than or equal to the expected sequence, this segment is valid.
            if seq >= expected_seq:
                segments.append((seq, packet))
                missing_num_bytes = seq - expected_seq
                if missing_num_bytes:
                    logger.debug(
                        f"Missing {missing_num_bytes} bytes of data between packets "
                        f"{prev_packet.frame} and {packet.frame}"
                    )
                expected_seq += missing_num_bytes + len(packet.data)
                prev_packet = packet

            # TODO: Support rollover sequence numbers.
            # Otherwise, we have some overlap in data and need to remove the invalid segment/packet
            # and ignoring adding it to the segments list.
            else:
                logger.debug(f"Packet {packet.frame} contains overlapped data. Removing...")
                self._remove_packet(packet)

        self._segments = segments  # cache for next time.
        return segments

    @property
    def data(self):
        """
        Raw data of tcp message.
        """
        # Return cache if set.
        if self._data is not None:
            return self._data

        # If not a TCP connection, just join packet data as they arrived on the wire.
        # TODO: Move this logic to a base class.
        if self.packets[0].tcp_flags is None:
            return b''.join(packet.data for packet in self.packets)

        # Join packet data based on segment data.
        data = bytearray()  # using bytearray to improve speed.
        initial_seq = None
        for seq, packet in self.segments:
            if initial_seq is None:
                initial_seq = seq

            # Check if we have missing packets.
            if seq - initial_seq != len(data):
                # buffer data with null bytes
                data += b'\x00' * (seq - initial_seq - len(data))

            data += packet.data
        data = bytes(data)

        self._data = data  # set cache
        return data

    @data.setter
    def data(self, data):
        """
        Replaces message data with new data.

        WARNING: Currently, data must match original length.
        """
        # TODO: Support different amount of bytes by adding packets or padding/removing packets.
        orig_len = len(self.data)
        if len(data) != orig_len:
            raise ValueError(
                f'Message data must be of the same length as original. '
                f'Expected {orig_len} bytes, got {len(data)} bytes.')

        # If not a TCP connection, just add data to packets in same order they arrived on wire.
        if self.packets[0].tcp_flags is None:
            written_bytes = 0
            for packet in self.packets:
                packet.data = data[written_bytes : written_bytes + len(packet.data)]
                written_bytes += len(packet.data)
            # Clear old cache.
            self._data = None
            return

        # If TCP connection, add data based on sequence numbers.
        written_bytes = 0
        initial_seq = None
        for seq, packet in self.segments:
            if initial_seq is None:
                initial_seq = seq

            relative_seq = seq - initial_seq
            if relative_seq < written_bytes:
                raise RuntimeError(
                    "Relative sequence is less then written byte count. "
                    "Sequence numbers have be miss-calculated."
                )
            # Skip holes in data. (User should have put padding in these areas)
            elif relative_seq != written_bytes:
                written_bytes = relative_seq

            packet.data = data[written_bytes:written_bytes + len(packet.data)]
            written_bytes += len(packet.data)

        # Clear old cache.
        self._data = None

    # TODO: Merge this in with the add_packet() logic, however I am unsure how using acknowledge numbers
    #   works if we are only looking at one side.
    def reassemble(self, allow_padding=True, allow_overlap=True, padding=b'\x00'):
        """
        Rebuild the data string from the current list of data packets
        For each packet, the TCP sequence number is checked.

        If overlapping or padding is disallowed, it will raise a
        SequenceNumberError exception if a respective event occurs.

        Args:
            allow_padding (bool):   If data is missing and allow_padding = True
                                    (default: True), then the padding argument
                                    will be used to fill the gaps.
            allow_overlap (bool):   If data is overlapping, the new data is
                                    used if the allow_overlap argument is True
                                    (default). Otherwise, the earliest data is
                                    kept.
            padding:    Byte character(s) to use to fill in missing data. Used
                        in conjunction with allow_padding (default: b'\\\\x00')
        """
        data = b""
        unacknowledged_data = []
        acknowledged_data = {}
        for pkt in self.packets:
            if not pkt.sequence_number:
                # if there are no sequence numbers (i.e. not TCP), just rebuild
                # in chronological order
                data += pkt.data
                continue

            if pkt.data:
                if pkt.sequence_number in acknowledged_data:
                    continue
                unacknowledged_data.append(pkt)

            elif pkt.tcp_flags and pkt.tcp_flags & tcp.TH_ACK:
                ackpkt = pkt
                for i, datapkt in enumerate(unacknowledged_data):
                    if (datapkt.ack_number == ackpkt.sequence_number
                            and ackpkt.ack_number == (datapkt.sequence_number + len(datapkt.data))):
                        # if the seq/ack numbers align, this is the data packet
                        # we want
                        # TODO confirm this logic is correct
                        acknowledged_data[datapkt.sequence_number] = datapkt.data
                        unacknowledged_data.pop(i)
                        break

        if not acknowledged_data and not unacknowledged_data:
            # For non-sequential protocols, just return what we have
            self.__data_bytes = data

        else:
            # Create a list of each segment of the complete data. Use
            # acknowledged data first, and then try to fill in the blanks with
            # unacknowledged data.
            segments = acknowledged_data.copy()
            for pkt in reversed(unacknowledged_data):
                if pkt.sequence_number in segments: continue
                segments[pkt.sequence_number] = pkt.data

            offsets = sorted(segments.keys())
            # iterate over the segments and try to piece them together
            # handle any instances of missing or overlapping segments
            nextoffset = offsets[0]
            startoffset = offsets[0]
            for offset in offsets:
                if offset > nextoffset:
                    # data is missing
                    if allow_padding:
                        data += padding * (offset - nextoffset)
                    else:
                        raise SequenceNumberError("Missing data for sequence number %d %s" % (nextoffset, self.addr))
                elif offset < nextoffset:
                    # data is overlapping
                    if not allow_overlap:
                        raise SequenceNumberError(
                            "Overlapping data for sequence number %d %s" % (nextoffset, self.addr))

                nextoffset = (offset + len(segments[offset])) & self.MAX_OFFSET
                data = data[:offset - startoffset] + \
                       segments[offset] + \
                       data[nextoffset - startoffset:]
            self.__data_bytes = data

        return data

    #        segments = {}
    #        for pkt in self.data_packets:
    #            if pkt.sequence_number:
    #                segments.setdefault(pkt.sequence_number, []).append(pkt.data)
    #            else:
    #                # if there are no sequence numbers (i.e. not TCP), just rebuild
    #                # in chronological order
    #                data += pkt.data
    #
    #        if not segments:
    #            # For non-sequential protocols, just return what we have
    #            self.__data_bytes = data
    #            return data
    #
    #        offsets = sorted(segments.keys())
    #
    #        # iterate over the segments and try to piece them together
    #        # handle any instances of missing or overlapping segments
    #        nextoffset = offsets[0]
    #        startoffset = offsets[0]
    #        for offset in offsets:
    #            # TODO do we still want to implement custom error handling?
    #            if offset > nextoffset:
    #                # data is missing
    #                if allow_padding:
    #                    data += padding * (offset - nextoffset)
    #                else:
    #                    raise SequenceNumberError("Missing data for sequence number %d %s" % (nextoffset, self.addr))
    #            elif offset < nextoffset:
    #                # data is overlapping
    #                if not allow_overlap:
    #                    raise SequenceNumberError("Overlapping data for sequence number %d %s" % (nextoffset, self.addr))
    ##            nextoffset = (offset + len(segments[offset][dup])) & self.MAX_OFFSET
    ##            if nextoffset in self.ack_sequence_numbers:
    #            if offset in self.ack_sequence_numbers:
    #                # If the data packet was acknowledged by the receiver,
    #                # we use the first packet received.
    #                dup = 0
    #            else:
    #                # If it went unacknowledged, we use the last packet and hope
    #                # for the best.
    #                dup = -1
    #            print(dup)
    #            print(offset)
    #            print(nextoffset)
    #            print(str(self.ack_sequence_numbers))
    #            nextoffset = (offset + len(segments[offset][dup])) & self.MAX_OFFSET
    #            data = data[:offset - startoffset] + \
    #                   segments[offset][dup] + \
    #                   data[nextoffset - startoffset:]
    #        self.__data_bytes = data
    #        return data

    def info(self):
        """
        Provides a dictionary with information about a blob. Useful for
        calls to a plugin's write() function, e.g. self.write(\\*\\*blob.info())

        Returns:
            Dictionary with information
        """
        d = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        del d['hidden']
        del d['packets']
        return d


    # TODO: Trying to determine if we should do this or take into account acknowledgement numbers
    #   like originally implemented.
    #   Perhaps rewrite their assemble to do some work in add_packet()?
    #   Do we want to ensure all segments are acknowledged or should we avoid that so we can handle
    #   partial/corrupt pcaps?
    def add_packet(self, packet):
        """
        Accepts a Packet object and stores it.

        Args:
            packet: a Packet object
        """
        # Clear old data and segment cache.
        self._data = None
        self._segments = None

        seq = packet.sequence_number

        # If packet is not TCP just add packet to list.
        if seq is None:
            self.packets.append(packet)
            if packet.ts < self.starttime: self.starttime = packet.ts
            if packet.ts > self.endtime: self.endtime = packet.ts
            return

        # If this a new sequence number we haven't seen before, add it to the map.
        if seq not in self._seq_map:
            self._seq_map[seq] = packet
            if seq < self.seq_min: self.seq_min = seq
            if seq > self.seq_max: self.seq_max = seq
            if packet.ts < self.starttime: self.starttime = packet.ts
            if packet.ts > self.endtime: self.endtime = packet.ts
            self.packets.append(packet)
            return

        # Otherwise, if we already have the packet for the given sequence
        # then we have a retransmission and will need to determine which packet to keep
        # and possibly remove other packets if this packet overlaps them.
        orig_packet = self._seq_map[seq]

        # ignore duplicate packet.
#        if len(packet.data) <= len(orig_packet.data):
        if packet.data == orig_packet.data:
            # TODO: should we still handle duplicate packets.
            logger.debug(f'Ignoring duplicate packet: {packet.frame}')
            return

        # If this packet would create more inconsistencies in our sequence numbers (more holes)
        # than the packet to be replaced, then this is most likely an out-of-order packet that the
        # sender has ignored, and we should too.
        orig_next_seq = seq + len(orig_packet.data)
        next_seq = seq + len(packet.data)
        if (
#            next_seq < max(self.sequence_numbers)
            next_seq < self.seq_max
            and orig_packet.data
            and next_seq not in self._seq_map
            and orig_next_seq in self._seq_map
        ):
            logger.debug(f'Ignoring out-of-order packet: {packet.frame}')
            return

        # Replace packet(s) with retransmitted packet

        # First add the retransmitted packet, replacing the original packet matching the
        # sequence number.
        logger.debug(f'Replacing packet {orig_packet.frame} with {packet.frame}')
        self._seq_map[seq] = packet
        self.packets = [packet if p.sequence_number == seq else p for p in self.packets]
        if packet.ts < self.starttime: self.starttime = packet.ts
        if packet.ts > self.endtime: self.endtime = packet.ts

        # Now remove any packets that contained data that is now part of the retransmitted packet.
        packets_to_remove = []
        for seq_, packet_ in self._seq_map.items():
            if 0 < (seq_ - seq) < len(packet.data):
                logger.debug(f'Removing packet: {packet_.frame}')
                packets_to_remove.append(packet_)
        # NOTE: need to remove packets outside the above loop because removing packets affect seq_map
        for packet_ in packets_to_remove:
            self._remove_packet(packet_)

    def _remove_packet(self, packet):
        """
        Removes packet from Blob. (internal use only)
        """
        # Clear old data and segment cache.
        self._data = None
        self._segments = None

        for seq, packet_ in list(self._seq_map.items()):
            if packet_ == packet:
                del self._seq_map[seq]
                if seq == self.seq_max:
                    self.seq_max = max(self._seq_map.keys())

        self.packets.remove(packet)
"""
A filter for connections by IP address country code. Generally used in conjunction
with other plugins.
"""



class DshellPlugin(dshell.core.ConnectionPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(
            name="Country Filter",
            bpf='ip or ip6',
            description="Filter connections by IP address country code",
            longdescription="""
country: Filter connections based on geolocation (country code).

Mandatory option:

  --country_code: Specify the 2-character country code to filter on.

Default behavior:

  If either the client or server IP address matches the specified country,
  the stream will be included.

Modifier options:

  --country_neither: Include only streams where neither the client nor the
                     server IP address matches the specified country.

  --country_both:    Include only streams where both the client AND the server
                     IP addresses match the specified country.

  --country_notboth: Include streams where the specified country is NOT BOTH
                     the client and server IP. Streams where it is one or
                     the other may be included.

  --country_alerts:  Show alerts for this plugin (default: false).

Example:

  decode -d country+pcapwriter traffic.pcap --pcapwriter_outfile=USonly.pcap --country_code US
  decode -d country+followstream traffic.pcap --country_code US --country_notboth
""",
            author="tp",
            output=NetflowOutput(label=__name__),
            optiondict={
                'code': {'type': str, 'help': 'Two-character country code', 'metavar': 'CC'},
                'neither': {'action': 'store_true', 'help': 'Neither (client/server) is in specified country'},
                'both': {'action': 'store_true', 'help': 'Both (client/server) ARE in specified country'},
                'notboth': {'action': 'store_true', 'help': 'Specified country is not both client and server'},
                'alerts': {'action': 'store_true', 'default': False, 'help': 'Show alerts for matches'}
            },
        )

    def premodule(self):
        # Check for mutually exclusive arguments
        if (self.neither + self.both + self.notboth) > 1:
            self.logger.warning("Only one of 'neither', 'both', or 'notboth' can be used at a time.")

    def connection_handler(self, conn):
        # If no country code specified, pass all traffic through
        if not self.code:
            return conn

        if self.neither:
            if conn.clientcc != self.code and conn.servercc != self.code:
                if self.alerts:
                    self.write('neither', **conn.info())
                return conn

        elif self.both:
            if conn.clientcc == self.code and conn.servercc == self.code:
                if self.alerts:
                    self.write('both', **conn.info())
                return conn

        elif self.notboth:
            if (conn.clientcc != self.code and conn.servercc == self.code) or \
               (conn.clientcc == self.code and conn.servercc != self.code):
                if self.alerts:
                    self.write('notboth', **conn.info())
                return conn

        else:
            if conn.clientcc == self.code or conn.servercc == self.code:
                if self.alerts:
                    self.write('match', **conn.info())
                return conn

        # No match
        return None

if __name__ == "__main__":
    print(DshellPlugin())


__all__ = [
    "CRL",
    "FILETYPE_ASN1",
    "FILETYPE_PEM",
    "FILETYPE_TEXT",
    "TYPE_DSA",
    "TYPE_RSA",
    "X509",
    "Error",
    "PKey",
    "Revoked",
    "X509Extension",
    "X509Req",
    "X509Store",
    "X509StoreContext",
    "X509StoreContextError",
    "X509StoreFlags",
    "dump_certificate",
    "dump_certificate_request",
    "dump_crl",
    "dump_privatekey",
    "dump_publickey",
    "load_certificate",
    "load_certificate_request",
    "load_crl",
    "load_privatekey",
    "load_publickey",
    "sign",
    "verify",
]

_PrivateKey = Union[
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
]

_PublicKey = Union[
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    rsa.RSAPublicKey,
]
class PathLike:
    """
    A class representing a path-like object that can be used where a path string or bytes is expected.
    """

    def __init__(self, path: Union[str, bytes]) -> None:
        if isinstance(path, (str, bytes)):
            self._path = path
        else:
            raise TypeError("Path must be a string or bytes")

    def __fspath__(self) -> str:
        if isinstance(self._path, bytes):
            return self._path.decode('utf-8')
        return self._path

    def __repr__(self) -> str:
        return f"PathLike({self._path!r})"

    def __str__(self) -> str:
        return self.__fspath__()


_Key = Union[_PrivateKey, _PublicKey]
StrOrBytesPath = Union[str, bytes, PathLike]
PassphraseCallableT = Union[bytes, Callable[..., bytes]]

FILETYPE_PEM: int = _lib.SSL_FILETYPE_PEM
FILETYPE_ASN1: int = _lib.SSL_FILETYPE_ASN1
FILETYPE_TEXT = 2**16 - 1  # TODO: This was an API mistake. OpenSSL has no such constant.
TYPE_RSA: int = _lib.EVP_PKEY_RSA
TYPE_DSA: int = _lib.EVP_PKEY_DSA
TYPE_DH: int = _lib.EVP_PKEY_DH
TYPE_EC: int = _lib.EVP_PKEY_EC





class Error(Exception):
    """An error occurred in an `OpenSSL.crypto` API."""
    pass

_raise_current_error = partial(_exception_from_error_queue, Error)
_openssl_assert = _make_assert(Error)


def _new_mem_buf(buffer: bytes | None = None) -> Any:
    """
    Allocate a new OpenSSL memory BIO.

    :param buffer: None or some bytes to use to put into the BIO so that they
        can be read out.
    """
    if buffer is None:
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        free = _lib.BIO_free
    else:
        data = _ffi.new("char[]", buffer)
        bio = _lib.BIO_new_mem_buf(data, len(buffer))
        free = lambda bio: _lib.BIO_free(bio)

    _openssl_assert(bio != _ffi.NULL)
    bio = _ffi.gc(bio, free)
    return bio


def _bio_to_string(bio: Any) -> bytes:
    """
    Copy the contents of an OpenSSL BIO object into a Python byte string.
    """
    result_buffer = _ffi.new("char**")
    buffer_length = _lib.BIO_get_mem_data(bio, result_buffer)
    return _ffi.buffer(result_buffer[0], buffer_length)[:]


def _set_asn1_time(boundary: Any, when: bytes) -> None:
    """
    Set the time value of an ASN1 time object.

    :param boundary: An ASN1_TIME pointer which will have its value set.
    :param when: A string representation of the desired time value.
    :raises TypeError: If `when` is not a byte string.
    :raises ValueError: If `when` does not represent a time in the required format.
    """
    if not isinstance(when, bytes):
        raise TypeError("when must be a byte string")

    _openssl_assert(boundary != _ffi.NULL)
    if _lib.ASN1_TIME_set_string(boundary, when) == 0:
        raise ValueError("Invalid string")


def _new_asn1_time(when: bytes) -> Any:
    """
    Create a new ASN1_TIME object and set its value.

    :param when: A string representation of the desired time value.
    :raises TypeError: If `when` is not a byte string.
    :raises ValueError: If `when` does not represent a time in the required format.
    """
    ret = _lib.ASN1_TIME_new()
    _openssl_assert(ret != _ffi.NULL)
    ret = _ffi.gc(ret, _lib.ASN1_TIME_free)
    _set_asn1_time(ret, when)
    return ret


def _get_asn1_time(timestamp: Any) -> bytes | None:
    """
    Retrieve the time value of an ASN1 time object.

    :param timestamp: An ASN1_TIME pointer from which the time value will be retrieved.
    :return: The time value from `timestamp` as a bytes string or None.
    """
    string_timestamp = _ffi.cast("ASN1_STRING*", timestamp)
    if _lib.ASN1_STRING_length(string_timestamp) == 0:
        return None

    if _lib.ASN1_STRING_type(string_timestamp) == _lib.V_ASN1_GENERALIZEDTIME:
        return _ffi.string(_lib.ASN1_STRING_get0_data(string_timestamp))

    generalized_timestamp = _ffi.new("ASN1_GENERALIZEDTIME**")
    _lib.ASN1_TIME_to_generalizedtime(timestamp, generalized_timestamp)
    _openssl_assert(generalized_timestamp[0] != _ffi.NULL)

    string_data = _lib.ASN1_STRING_get0_data(generalized_timestamp[0])
    result = _ffi.string(string_data)
    _lib.ASN1_GENERALIZEDTIME_free(generalized_timestamp[0])
    return result


class _X509NameInvalidator:
    def __init__(self) -> None:
        self._names: list[X509] = []

    def add(self, name: X509) -> None:
        self._names.append(name)

    def clear(self) -> None:
        for name in self._names:
            del name._name


class Encoding:
    DER = 0


class PrivateFormat:
    PKCS8 = 0


class NoEncryption:
    pass


class PublicFormat:
    SubjectPublicKeyInfo = 0


class partial:
    def __init__(self, func: Type, *args: Any, **kwargs: Any) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.update(self.kwargs)
        return self.func(*(self.args + args), **kwargs)


class PKey:
    """
    A class representing an RSA or DSA public key or key pair.
    """
    _only_public = False
    _initialized = True

    def __init__(self) -> None:
        self._pkey = _ffi.gc(_lib.EVP_PKEY_new(), _lib.EVP_PKEY_free)
        self._initialized = False

    def to_cryptography_key(self) -> Any:
        """
        Export as a `cryptography` key.
        """
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key,
            load_der_public_key,
        )

        if self._only_public:
            der = dump_publickey(Encoding.DER, self)
            return load_der_public_key(der)
        else:
            der = dump_privatekey(Encoding.DER, self)
            return load_der_private_key(der, None)


# Define constants
TYPE_RSA = _lib.EVP_PKEY_RSA
TYPE_DSA = _lib.EVP_PKEY_DSA
TYPE_EC = _lib.EVP_PKEY_EC
FILETYPE_PEM = _lib.SSL_FILETYPE_PEM
FILETYPE_ASN1 = _lib.SSL_FILETYPE_ASN1
FILETYPE_TEXT = 2**16 - 1

# Define X509StoreFlags as needed
class X509StoreFlags:
    # Define the flags based on library constants or requirements
    FLAG_ONE = 0x01
    FLAG_TWO = 0x02
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec

class PKey:
    def __init__(self) -> None:
        # Initialize the key attribute (you can use a different structure or library for your keys)
        self._pkey = None
        self._initialized = False
    
    def _initialize_key(self, crypto_key: Any, key_id: int) -> None:
        """
        Initialize the PKey instance with the provided cryptography key and type ID.

        :param crypto_key: The cryptography key to be assigned.
        :param key_id: The type ID of the key (e.g., TYPE_RSA, TYPE_DSA, etc.).
        """
        if key_id == TYPE_RSA:
            if not isinstance(crypto_key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
                raise TypeError("Expected RSA key type")
        elif key_id == TYPE_DSA:
            if not isinstance(crypto_key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
                raise TypeError("Expected DSA key type")
        elif key_id == TYPE_EC:
            if not isinstance(crypto_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
                raise TypeError("Expected EC key type")
        else:
            raise ValueError("Unsupported key type ID")

        # Assign the key to the internal attribute
        self._pkey = crypto_key
        self._initialized = True
def handle_key(crypto_key: Any) -> 'PKey':
    # Define how to handle different key types
    key_type_mapping = {
        dsa.DSAPrivateKey: TYPE_DSA,
        dsa.DSAPublicKey: TYPE_DSA,
        ec.EllipticCurvePrivateKey: TYPE_EC,
        ec.EllipticCurvePublicKey: TYPE_EC,
        rsa.RSAPrivateKey: TYPE_RSA,
        rsa.RSAPublicKey: TYPE_RSA,
    }

    key_type = type(crypto_key)
    if key_type not in key_type_mapping:
        raise TypeError("Unsupported key type")

    key_id = key_type_mapping[key_type]
    
    pkey = PKey()  # Create an instance of PKey
    pkey._initialize_key(crypto_key, key_id)
    return pkey


def _initialize_key(self: 'PKey', crypto_key: Any, key_id: int) -> None:
    # Initialize the key based on the key type
    if key_id == TYPE_RSA:
        self._pkey = _lib.EVP_PKEY_new()
        rsa_key = crypto_key.private_numbers()
        rsa = _lib.RSA_new()
        # Load RSA key components
        # Assume methods for setting RSA key components here
        _lib.EVP_PKEY_assign_RSA(self._pkey, rsa)
    elif key_id == TYPE_DSA:
        self._pkey = _lib.EVP_PKEY_new()
        dsa_key = crypto_key.private_numbers()
        dsa = _lib.DSA_new()
        # Load DSA key components
        # Assume methods for setting DSA key components here
        _lib.EVP_PKEY_set1_DSA(self._pkey, dsa)
    elif key_id == TYPE_EC:
        self._pkey = _lib.EVP_PKEY_new()
        ec_key = crypto_key.private_numbers()
        ec = _lib.EC_KEY_new_by_curve_name(ec_key.curve.name)
        # Load EC key components
        # Assume methods for setting EC key components here
        _lib.EVP_PKEY_set1_EC_KEY(self._pkey, ec)
    else:
        raise TypeError("Unsupported key type")

class PKey:
    def __init__(self):
        self._pkey = None
        self._initialized = False
        self._only_public = False

    @classmethod
    def from_cryptography_key(cls, crypto_key: Any) -> 'PKey':
        """
        Construct based on a `cryptography` *crypto_key*.
        """
        from cryptography.hazmat.primitives import serialization as ser

        key_mapping = {
            ser.dsa.DSAPrivateKey: TYPE_DSA,
            ser.dsa.DSAPublicKey: TYPE_DSA,
            ser.ec.EllipticCurvePrivateKey: TYPE_EC,
            ser.ec.EllipticCurvePublicKey: TYPE_EC,
            ser.rsa.RSAPrivateKey: TYPE_RSA,
            ser.rsa.RSAPublicKey: TYPE_RSA,
        }

        for key_type, key_id in key_mapping.items():
            if isinstance(crypto_key, key_type):
                return handle_key(crypto_key)

        raise TypeError("Unsupported key type")

    def generate_key(self, type: int, bits: int) -> None:
        """
        Generate a key pair of the given type, with the given number of bits.
        """
        if not isinstance(type, int) or not isinstance(bits, int):
            raise TypeError("type and bits must be integers")

        if type == TYPE_RSA:
            if bits <= 0:
                raise ValueError("Invalid number of bits")
            exponent = _lib.BN_new()
            _lib.BN_set_word(exponent, _lib.RSA_F4)
            rsa = _lib.RSA_new()
            if _lib.RSA_generate_key_ex(rsa, bits, exponent, _ffi.NULL) != 1:
                raise Error("Failed to generate RSA key")
            if _lib.EVP_PKEY_assign_RSA(self._pkey, rsa) != 1:
                raise Error("Failed to assign RSA key")
        elif type == TYPE_DSA:
            dsa = _lib.DSA_new()
            if dsa == _ffi.NULL:
                raise Error("Failed to create DSA key")
            if _lib.DSA_generate_parameters_ex(dsa, bits, _ffi.NULL, 0, _ffi.NULL, _ffi.NULL, _ffi.NULL) != 1:
                raise Error("Failed to generate DSA parameters")
            if _lib.DSA_generate_key(dsa) != 1:
                raise Error("Failed to generate DSA key")
            if _lib.EVP_PKEY_set1_DSA(self._pkey, dsa) != 1:
                raise Error("Failed to assign DSA key")
        else:
            raise Error("No such key type")

        self._initialized = True

    def check(self) -> bool:
        """
        Check the consistency of an RSA private key.
        """
        if self._only_public:
            raise TypeError("Public key only")

        if _lib.EVP_PKEY_type(self.type()) != _lib.EVP_PKEY_RSA:
            raise TypeError("Only RSA keys can currently be checked.")

        rsa = _lib.EVP_PKEY_get1_RSA(self._pkey)
        if _lib.RSA_check_key(rsa) == 1:
            return True
        _raise_current_error()

    def type(self) -> int:
        """
        Returns the type of the key.
        """
        return _lib.EVP_PKEY_id(self._pkey)

    def get_components(self) -> List[Tuple[bytes, bytes]]:
        """
        Get the key components.
        """
        components = []
        for i in range(_lib.X509_NAME_entry_count(self._name)):
            entry = _lib.X509_NAME_get_entry(self._name, i)
            obj = _lib.X509_NAME_ENTRY_get_object(entry)
            nid = _lib.OBJ_obj2nid(obj)
            data = _lib.X509_NAME_ENTRY_get_data(entry)
            result_buffer = _ffi.new("unsigned char**")
            data_length = _lib.ASN1_STRING_to_UTF8(result_buffer, data)
            if data_length >= 0:
                try:
                    value = _ffi.buffer(result_buffer[0], data_length)[:]
                finally:
                    _lib.OPENSSL_free(result_buffer[0])
                attr_name = _ffi.string(_lib.OBJ_nid2ln(nid)).decode("ascii")
                components.append((attr_name.encode("utf-8"), value))
        return components


# Define type aliases for better readability
X509 = Any  # Replace 'Any' with the actual type if known
GENERAL_NAMES = Any  # Replace 'Any' with the actual type if known
ASN1_STRING = Any  # Replace 'Any' with the actual type if known

class X509Extension:
    """
    An X.509 v3 certificate extension.
    """

    def __init__(
        self,
        type_name: bytes,
        critical: bool,
        value: bytes,
        subject: Optional[X509] = None,
        issuer: Optional[X509] = None,
    ) -> None:
        """
        Initializes an X509 extension.

        :param type_name: The name of the type of extension to create.
        :type type_name: bytes

        :param critical: A flag indicating whether this is a critical extension.
        :type critical: bool

        :param value: The OpenSSL textual representation of the extension's value.
        :type value: bytes

        :param subject: Optional X509 certificate to use as subject.
        :type subject: Optional[X509]

        :param issuer: Optional X509 certificate to use as issuer.
        :type issuer: Optional[X509]
        """
        ctx = _ffi.new("X509V3_CTX*")
        _lib.X509V3_set_ctx(ctx, _ffi.NULL, _ffi.NULL, _ffi.NULL, _ffi.NULL, 0)
        _lib.X509V3_set_ctx_nodb(ctx)

        if issuer is not None:
            if not isinstance(issuer, X509):
                raise TypeError("issuer must be an X509 instance")
            ctx.issuer_cert = issuer._x509
        if subject is not None:
            if not isinstance(subject, X509):
                raise TypeError("subject must be an X509 instance")
            ctx.subject_cert = subject._x509

        if critical:
            value = b"critical," + value

        extension = _lib.X509V3_EXT_nconf(_ffi.NULL, ctx, type_name, value)
        if extension == _ffi.NULL:
            _raise_current_error()
        self._extension = _ffi.gc(extension, _lib.X509_EXTENSION_free)

    @property
    def _nid(self) -> int:
        """Return the NID of the extension object."""
        return _lib.OBJ_obj2nid(_lib.X509_EXTENSION_get_object(self._extension))

    _prefixes: ClassVar[Dict[int, str]] = {
        _lib.GEN_EMAIL: "email",
        _lib.GEN_DNS: "DNS",
        _lib.GEN_URI: "URI",
    }

    def _subjectAltNameString(self) -> str:
        """Return a string representation of the Subject Alternative Names."""
        names = _ffi.cast("GENERAL_NAMES*", _lib.X509V3_EXT_d2i(self._extension))
        names = _ffi.gc(names, _lib.GENERAL_NAMES_free)
        parts = []
        for i in range(_lib.sk_GENERAL_NAME_num(names)):
            name = _lib.sk_GENERAL_NAME_value(names, i)
            try:
                label = self._prefixes[name.type]
            except KeyError:
                bio = _new_mem_buf()
                _lib.GENERAL_NAME_print(bio, name)
                parts.append(_bio_to_string(bio).decode("utf-8"))
            else:
                value = _ffi.buffer(name.d.ia5.data, name.d.ia5.length)[:].decode("utf-8")
                parts.append(f"{label}:{value}")
        return ", ".join(parts)

    def __str__(self) -> str:
        """
        Return a text representation of the extension.
        """
        if _lib.NID_subject_alt_name == self._nid:
            return self._subjectAltNameString()

        bio = _new_mem_buf()
        if _lib.X509V3_EXT_print(bio, self._extension, 0, 0) == 0:
            raise RuntimeError("Failed to print extension")
        return _bio_to_string(bio).decode("utf-8")

    def get_critical(self) -> bool:
        """
        Return whether the extension is critical.
        """
        return _lib.X509_EXTENSION_get_critical(self._extension) != 0

    def get_short_name(self) -> bytes:
        """
        Return the short type name of the extension.
        """
        obj = _lib.X509_EXTENSION_get_object(self._extension)
        nid = _lib.OBJ_obj2nid(obj)
        buf = _lib.OBJ_nid2sn(nid)
        return _ffi.string(buf) if buf != _ffi.NULL else b"UNDEF"

    def get_data(self) -> bytes:
        """
        Return the ASN.1 encoded data of the extension.
        """
        octet_result = _lib.X509_EXTENSION_get_data(self._extension)
        string_result = _ffi.cast("ASN1_STRING*", octet_result)
        char_result = _lib.ASN1_STRING_get0_data(string_result)
        result_length = _lib.ASN1_STRING_length(string_result)
        return _ffi.buffer(char_result, result_length)[:]

# Deprecation handling
_X509ExtensionInternal = X509Extension
utils.deprecated(
    X509Extension,
    __name__,
    (
        "X509Extension support in pyOpenSSL is deprecated. You should use the "
        "APIs in cryptography."
    ),
    DeprecationWarning,
    name="X509Extension",
)




class X509Req:
    """
    Represents an X.509 certificate signing request (CSR).
    """

    def __init__(self) -> None:
        req = _lib.X509_REQ_new()
        self._req = _ffi.gc(req, _lib.X509_REQ_free)
        self.set_version(0)

    def to_cryptography(self) -> x509.CertificateSigningRequest:
        """
        Export as a ``cryptography`` certificate signing request.
        """
        der = _dump_certificate_request_internal(FILETYPE_ASN1, self)
        return x509.load_der_x509_csr(der)

@classmethod
def from_cryptography(cls, crypto_req: x509.CertificateSigningRequest) -> 'X509Req':
    """
    Construct from a ``cryptography`` certificate signing request.
    """
    if not isinstance(crypto_req, x509.CertificateSigningRequest):
        raise TypeError("Must be a certificate signing request")
    
    # Get the DER-encoded CSR bytes from the cryptography object
    der = crypto_req.public_bytes(Encoding.DER)
    
    # Create a new X509Req instance
    req = X509Req()
    
    # Create a BIO object from the DER-encoded data
    bio = _ffi.gc(_lib.BIO_new_mem_buf(der, len(der)), _lib.BIO_free_all)
    
    # Load the CSR from the BIO object
    req_ptr = _lib.d2i_X509_REQ_bio(bio, _ffi.NULL)
    if req_ptr == _ffi.NULL:
        _raise_current_error()  # Handle the error if CSR loading fails
    
    # Set the internal request pointer of the X509Req instance
    req._req = _ffi.gc(req_ptr, _lib.X509_REQ_free)
    
    return req

    def set_pubkey(self, pkey: PKey) -> None:
        """
        Set the public key of the certificate signing request.
        """
        set_result = _lib.X509_REQ_set_pubkey(self._req, pkey._pkey)
        _openssl_assert(set_result == 1)

    def get_pubkey(self) -> PKey:
        """
        Get the public key of the certificate signing request.
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _lib.X509_REQ_get_pubkey(self._req)
        _openssl_assert(pkey._pkey != _ffi.NULL)
        pkey._pkey = _ffi.gc(pkey._pkey, _lib.EVP_PKEY_free)
        pkey._only_public = True
        return pkey

    def set_version(self, version: int) -> None:
        """
        Set the version of the certificate signing request.
        """
        if version != 0:
            raise ValueError("Invalid version. The only valid version for X509Req is 0.")
        set_result = _lib.X509_REQ_set_version(self._req, version)
        _openssl_assert(set_result == 1)

    def get_version(self) -> int:
        """
        Get the version of the certificate signing request.
        """
        return _lib.X509_REQ_get_version(self._req)

    def get_subject(self) -> 'X509':
        """
        Return the subject of this certificate signing request.
        """
        name = X509.__new__(X509)
        name._name = _lib.X509_REQ_get_subject_name(self._req)
        _openssl_assert(name._name != _ffi.NULL)
        name._owner = self
        return name

    def add_extensions(self, extensions: Iterable['_X509ExtensionInternal']) -> None:
        """
        Add extensions to the certificate signing request.
        """
        warnings.warn(
            "This API is deprecated and will be removed in a future version of pyOpenSSL.",
            DeprecationWarning,
            stacklevel=2
        )
        stack = _ffi.gc(_lib.sk_X509_EXTENSION_new_null(), _lib.sk_X509_EXTENSION_free)
        for ext in extensions:
            if not isinstance(ext, _X509ExtensionInternal):
                raise ValueError("One of the elements is not an X509Extension")
            _lib.sk_X509_EXTENSION_push(stack, ext._extension)
        add_result = _lib.X509_REQ_add_extensions(self._req, stack)
        _openssl_assert(add_result == 1)

    def get_extensions(self) -> list['_X509ExtensionInternal']:
        """
        Get X.509 extensions in the certificate signing request.
        """
        warnings.warn(
            "This API is deprecated and will be removed in a future version of pyOpenSSL.",
            DeprecationWarning,
            stacklevel=2
        )
        exts = []
        native_exts_obj = _ffi.gc(
            _lib.X509_REQ_get_extensions(self._req),
            lambda x: _lib.sk_X509_EXTENSION_pop_free(
                x,
                _ffi.addressof(_lib._original_lib, "X509_EXTENSION_free")
            )
        )
        for i in range(_lib.sk_X509_EXTENSION_num(native_exts_obj)):
            ext = _X509ExtensionInternal.__new__(_X509ExtensionInternal)
            ext._extension = _ffi.gc(
                _lib.X509_EXTENSION_dup(_lib.sk_X509_EXTENSION_value(native_exts_obj, i)),
                _lib.X509_EXTENSION_free
            )
            exts.append(ext)
        return exts

    def sign(self, pkey: PKey, digest: str) -> None:
        """
        Sign the certificate signing request with this key and digest type.
        """
        if pkey._only_public:
            raise ValueError("Key has only public part")
        if not pkey._initialized:
            raise ValueError("Key is uninitialized")
        digest_obj = _lib.EVP_get_digestbyname(_byte_string(digest))
        if digest_obj == _ffi.NULL:
            raise ValueError("No such digest method")
        sign_result = _lib.X509_REQ_sign(self._req, pkey._pkey, digest_obj)
        _openssl_assert(sign_result > 0)

    def verify(self, pkey: PKey) -> bool:
        """
        Verifies the signature on this certificate signing request.
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")
        result = _lib.X509_REQ_verify(self._req, pkey._pkey)
        if result <= 0:
            _raise_current_error()
        return result


class X509:
    """
    Represents an X.509 certificate.
    """

    def __init__(self) -> None:
        x509 = _lib.X509_new()
        _openssl_assert(x509 != _ffi.NULL)
        self._x509 = _ffi.gc(x509, _lib.X509_free)
        self._issuer_invalidator = _X509NameInvalidator()
        self._subject_invalidator = _X509NameInvalidator()

    @classmethod
    def _from_raw_x509_ptr(cls, x509: Any) -> 'X509':
        cert = cls.__new__(cls)
        cert._x509 = _ffi.gc(x509, _lib.X509_free)
        cert._issuer_invalidator = _X509NameInvalidator()
        cert._subject_invalidator = _X509NameInvalidator()
        return cert

    def to_cryptography(self) -> x509.Certificate:
        """
        Export as a ``cryptography`` certificate.
        """
        der = dump_certificate(FILETYPE_ASN1, self)
        return x509.load_der_x509_certificate(der)

    @classmethod
    def from_cryptography(cls, crypto_cert: x509.Certificate) -> 'X509':
        """
        Construct from a ``cryptography`` certificate.
        """
        if not isinstance(crypto_cert, x509.Certificate):
            raise TypeError("Must be a certificate")
        der = crypto_cert.public_bytes(Encoding.DER)
        return load_certificate(FILETYPE_ASN1, der)

    def set_version(self, version: int) -> None:
        """
        Set the version number of the certificate.
        """
        if not isinstance(version, int):
            raise TypeError("version must be an integer")
        _openssl_assert(_lib.X509_set_version(self._x509, version) == 1)

    def get_version(self) -> int:
        """
        Return the version number of the certificate.
        """
        return _lib.X509_get_version(self._x509)

    def get_pubkey(self) -> PKey:
        """
        Get the public key of the certificate.
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _lib.X509_get_pubkey(self._x509)
        if pkey._pkey == _ffi.NULL:
            _raise_current_error()
        pkey._pkey = _ffi.gc(pkey._pkey, _lib.EVP_PKEY_free)
        pkey._only_public = True
        return pkey

    def set_pubkey(self, pkey: PKey) -> None:
        """
        Set the public key of the certificate.
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")
        set_result = _lib.X509_set_pubkey(self._x509, pkey._pkey)
        _openssl_assert(set_result == 1)

    def sign(self, pkey: PKey, digest: str) -> None:
        """
        Sign the certificate with this key and digest type.
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")
        if pkey._only_public:
            raise ValueError("Key only has public part")
        if not pkey._initialized:
            raise ValueError("Key is uninitialized")
        evp_md = _lib.EVP_get_digestbyname(_byte_string(digest))
        if evp_md == _ffi.NULL:
            raise ValueError("No such digest method")
        sign_result = _lib.X509_sign(self._x509, pkey._pkey, evp_md)
        _openssl_assert(sign_result > 0)

        def get_signature_algorithm(self) -> bytes:
            """
        Get the signature algorithm used in the certificate.
        """
        algo = _lib.X509_get_signature_algorithm(self._x509)
        if algo == _ffi.NULL:
            _raise_current_error()
        # Convert the ASN1_OBJECT to a bytes representation
        return _ffi.string(_lib.OBJ_nid2sn(_lib.OBJ_obj2nid(algo)))
   





class X509Store:
    """
    An X.509 store.

    An X.509 store is used to describe a context in which to verify a
    certificate. A description of a context may include a set of certificates
    to trust, a set of certificate revocation lists, verification flags and
    more.

    An X.509 store, being only a description, cannot be used by itself to
    verify a certificate. To carry out the actual verification process, see
    :class:`X509StoreContext`.
    """

    def __init__(self) -> None:
        store = _lib.X509_STORE_new()
        self._store = _ffi.gc(store, _lib.X509_STORE_free)

    def add_cert(self, cert: X509) -> None:
        """
        Adds a trusted certificate to this store.

        Adding a certificate with this method adds this certificate as a
        *trusted* certificate.

        :param X509 cert: The certificate to add to this store.

        :raises TypeError: If the certificate is not an :class:`X509`.

        :raises OpenSSL.crypto.Error: If OpenSSL was unhappy with your
            certificate.

        :return: ``None`` if the certificate was added successfully.
        """
        if not isinstance(cert, X509):
            raise TypeError()

        res = _lib.X509_STORE_add_cert(self._store, cert._x509)
        _openssl_assert(res == 1)

    def add_crl(
        self, crl: _CRLInternal | x509.CertificateRevocationList
    ) -> None:
        """
        Add a certificate revocation list to this store.

        The certificate revocation lists added to a store will only be used if
        the associated flags are configured to check certificate revocation
        lists.

        .. versionadded:: 16.1.0

        :param crl: The certificate revocation list to add to this store.
        :type crl: ``Union[CRL, cryptography.x509.CertificateRevocationList]``
        :return: ``None`` if the certificate revocation list was added
            successfully.
        """
        if isinstance(crl, x509.CertificateRevocationList):
            from cryptography.hazmat.primitives.serialization import Encoding

            bio = _new_mem_buf(crl.public_bytes(Encoding.DER))
            openssl_crl = _lib.d2i_X509_CRL_bio(bio, _ffi.NULL)
            _openssl_assert(openssl_crl != _ffi.NULL)
            crl = _ffi.gc(openssl_crl, _lib.X509_CRL_free)
        elif isinstance(crl, _CRLInternal):
            crl = crl._crl
        else:
            raise TypeError(
                "CRL must be of type OpenSSL.crypto.CRL or "
                "cryptography.x509.CertificateRevocationList"
            )

        _openssl_assert(_lib.X509_STORE_add_crl(self._store, crl) != 0)

    def set_flags(self, flags: int) -> None:
        """
        Set verification flags to this store.

        Verification flags can be combined by oring them together.

        .. note::

          Setting a verification flag sometimes requires clients to add
          additional information to the store, otherwise a suitable error will
          be raised.

          For example, in setting flags to enable CRL checking a
          suitable CRL must be added to the store otherwise an error will be
          raised.

        .. versionadded:: 16.1.0

        :param int flags: The verification flags to set on this store.
            See :class:`X509StoreFlags` for available constants.
        :return: ``None`` if the verification flags were successfully set.
        """
        _openssl_assert(_lib.X509_STORE_set_flags(self._store, flags) != 0)

    def set_time(self, vfy_time: datetime.datetime) -> None:
        """
        Set the time against which the certificates are verified.

        Normally the current time is used.

        .. note::

          For example, you can determine if a certificate was valid at a given
          time.

        .. versionadded:: 17.0.0

        :param datetime vfy_time: The verification time to set on this store.
        :return: ``None`` if the verification time was successfully set.
        """
        param = _lib.X509_VERIFY_PARAM_new()
        param = _ffi.gc(param, _lib.X509_VERIFY_PARAM_free)

        _lib.X509_VERIFY_PARAM_set_time(
            param, calendar.timegm(vfy_time.timetuple())
        )
        _openssl_assert(_lib.X509_STORE_set1_param(self._store, param) != 0)

    def load_locations(
        self, cafile: StrOrBytesPath, capath: StrOrBytesPath | None = None
    ) -> None:
        """
        Let X509Store know where we can find trusted certificates for the
        certificate chain.  Note that the certificates have to be in PEM
        format.

        If *capath* is passed, it must be a directory prepared using the
        ``c_rehash`` tool included with OpenSSL.  Either, but not both, of
        *cafile* or *capath* may be ``None``.

        .. note::

          Both *cafile* and *capath* may be set simultaneously.

          Call this method multiple times to add more than one location.
          For example, CA certificates, and certificate revocation list bundles
          may be passed in *cafile* in subsequent calls to this method.

        .. versionadded:: 20.0

        :param cafile: In which file we can find the certificates (``bytes`` or
                       ``unicode``).
        :param capath: In which directory we can find the certificates
                       (``bytes`` or ``unicode``).

        :return: ``None`` if the locations were set successfully.

        :raises OpenSSL.crypto.Error: If both *cafile* and *capath* is ``None``
            or the locations could not be set for any reason.

        """
        if cafile is None:
            cafile = _ffi.NULL
        else:
            cafile = _path_bytes(cafile)

        if capath is None:
            capath = _ffi.NULL
        else:
            capath = _path_bytes(capath)

        load_result = _lib.X509_STORE_load_locations(
            self._store, cafile, capath
        )
        if not load_result:
            _raise_current_error()


class X509StoreContextError(Exception):
    """
    An exception raised when an error occurred while verifying a certificate
    using `OpenSSL.X509StoreContext.verify_certificate`.

    :ivar certificate: The certificate which caused verificate failure.
    :type certificate: :class:`X509`
    """

    def __init__(
        self, message: str, errors: list[Any], certificate: X509
    ) -> None:
        super().__init__(message)
        self.errors = errors
        self.certificate = certificate


class X509StoreContext:
    """
    An X.509 store context.

    An X.509 store context is used to carry out the actual verification process
    of a certificate in a described context. For describing such a context, see
    :class:`X509Store`.

    :param X509Store store: The certificates which will be trusted for the
        purposes of any verifications.
    :param X509 certificate: The certificate to be verified.
    :param chain: List of untrusted certificates that may be used for building
        the certificate chain. May be ``None``.
    :type chain: :class:`list` of :class:`X509`
    """

    def __init__(
        self,
        store: X509Store,
        certificate: X509,
        chain: Sequence[X509] | None = None,
    ) -> None:
        self._store = store
        self._cert = certificate
        self._chain = self._build_certificate_stack(chain)

    @staticmethod
    def _build_certificate_stack(
        certificates: Sequence[X509] | None,
    ) -> None:
        def cleanup(s: Any) -> None:
            # Equivalent to sk_X509_pop_free, but we don't
            # currently have a CFFI binding for that available
            for i in range(_lib.sk_X509_num(s)):
                x = _lib.sk_X509_value(s, i)
                _lib.X509_free(x)
            _lib.sk_X509_free(s)

        if certificates is None or len(certificates) == 0:
            return _ffi.NULL

        stack = _lib.sk_X509_new_null()
        _openssl_assert(stack != _ffi.NULL)
        stack = _ffi.gc(stack, cleanup)

        for cert in certificates:
            if not isinstance(cert, X509):
                raise TypeError("One of the elements is not an X509 instance")

            _openssl_assert(_lib.X509_up_ref(cert._x509) > 0)
            if _lib.sk_X509_push(stack, cert._x509) <= 0:
                _lib.X509_free(cert._x509)
                _raise_current_error()

        return stack

    @staticmethod
    def _exception_from_context(store_ctx: Any) -> X509StoreContextError:
        """
        Convert an OpenSSL native context error failure into a Python
        exception.

        When a call to native OpenSSL X509_verify_cert fails, additional
        information about the failure can be obtained from the store context.
        """
        message = _ffi.string(
            _lib.X509_verify_cert_error_string(
                _lib.X509_STORE_CTX_get_error(store_ctx)
            )
        ).decode("utf-8")
        errors = [
            _lib.X509_STORE_CTX_get_error(store_ctx),
            _lib.X509_STORE_CTX_get_error_depth(store_ctx),
            message,
        ]
        # A context error should always be associated with a certificate, so we
        # expect this call to never return :class:`None`.
        _x509 = _lib.X509_STORE_CTX_get_current_cert(store_ctx)
        _cert = _lib.X509_dup(_x509)
        pycert = X509._from_raw_x509_ptr(_cert)
        return X509StoreContextError(message, errors, pycert)

    def _verify_certificate(self) -> Any:
        """
        Verifies the certificate and runs an X509_STORE_CTX containing the
        results.

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.
        """
        store_ctx = _lib.X509_STORE_CTX_new()
        _openssl_assert(store_ctx != _ffi.NULL)
        store_ctx = _ffi.gc(store_ctx, _lib.X509_STORE_CTX_free)

        ret = _lib.X509_STORE_CTX_init(
            store_ctx, self._store._store, self._cert._x509, self._chain
        )
        _openssl_assert(ret == 1)

        ret = _lib.X509_verify_cert(store_ctx)
        if ret <= 0:
            raise self._exception_from_context(store_ctx)

        return store_ctx

    def set_store(self, store: X509Store) -> None:
        """
        Set the context's X.509 store.

        .. versionadded:: 0.15

        :param X509Store store: The store description which will be used for
            the purposes of any *future* verifications.
        """
        self._store = store

    def verify_certificate(self) -> None:
        """
        Verify a certificate in a context.

        .. versionadded:: 0.15

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.
        """
        self._verify_certificate()

    def get_verified_chain(self) -> list[X509]:
        """
        Verify a certificate in a context and return the complete validated
        chain.

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.

        .. versionadded:: 20.0
        """
        store_ctx = self._verify_certificate()

        # Note: X509_STORE_CTX_get1_chain returns a deep copy of the chain.
        cert_stack = _lib.X509_STORE_CTX_get1_chain(store_ctx)
        _openssl_assert(cert_stack != _ffi.NULL)

        result = []
        for i in range(_lib.sk_X509_num(cert_stack)):
            cert = _lib.sk_X509_value(cert_stack, i)
            _openssl_assert(cert != _ffi.NULL)
            pycert = X509._from_raw_x509_ptr(cert)
            result.append(pycert)

        # Free the stack but not the members which are freed by the X509 class.
        _lib.sk_X509_free(cert_stack)
        return result


def load_certificate(type: int, buffer: bytes) -> X509:
    """
    Load a certificate (X509) from the string *buffer* encoded with the
    type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)

    :param bytes buffer: The buffer the certificate is stored in

    :return: The X509 object
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    if type == FILETYPE_PEM:
        x509 = _lib.PEM_read_bio_X509(bio, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        x509 = _lib.d2i_X509_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if x509 == _ffi.NULL:
        _raise_current_error()

    return X509._from_raw_x509_ptr(x509)


def dump_certificate(type: int, cert: X509) -> bytes:
    """
    Dump the certificate *cert* into a buffer string encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1, or
        FILETYPE_TEXT)
    :param cert: The certificate to dump
    :return: The buffer with the dumped certificate in
    """
    bio = _new_mem_buf()

    if type == FILETYPE_PEM:
        result_code = _lib.PEM_write_bio_X509(bio, cert._x509)
    elif type == FILETYPE_ASN1:
        result_code = _lib.i2d_X509_bio(bio, cert._x509)
    elif type == FILETYPE_TEXT:
        result_code = _lib.X509_print_ex(bio, cert._x509, 0, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or "
            "FILETYPE_TEXT"
        )

    _openssl_assert(result_code == 1)
    return _bio_to_string(bio)


def dump_publickey(type: int, pkey: PKey) -> bytes:
    """
    Dump a public key to a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM` or
        :data:`FILETYPE_ASN1`).
    :param PKey pkey: The public key to dump
    :return: The buffer with the dumped key in it.
    :rtype: bytes
    """
    bio = _new_mem_buf()
    if type == FILETYPE_PEM:
        write_bio = _lib.PEM_write_bio_PUBKEY
    elif type == FILETYPE_ASN1:
        write_bio = _lib.i2d_PUBKEY_bio
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    result_code = write_bio(bio, pkey._pkey)
    if result_code != 1:  # pragma: no cover
        _raise_current_error()

    return _bio_to_string(bio)


def dump_privatekey(
    type: int,
    pkey: PKey,
    cipher: str | None = None,
    passphrase: PassphraseCallableT | None = None,
) -> bytes:
    """
    Dump the private key *pkey* into a buffer string encoded with the type
    *type*.  Optionally (if *type* is :const:`FILETYPE_PEM`) encrypting it
    using *cipher* and *passphrase*.

    :param type: The file type (one of :const:`FILETYPE_PEM`,
        :const:`FILETYPE_ASN1`, or :const:`FILETYPE_TEXT`)
    :param PKey pkey: The PKey to dump
    :param cipher: (optional) if encrypted PEM format, the cipher to use
    :param passphrase: (optional) if encrypted PEM format, this can be either
        the passphrase to use, or a callback for providing the passphrase.

    :return: The buffer with the dumped key in
    :rtype: bytes
    """
    bio = _new_mem_buf()

    if not isinstance(pkey, PKey):
        raise TypeError("pkey must be a PKey")

    if cipher is not None:
        if passphrase is None:
            raise TypeError(
                "if a value is given for cipher "
                "one must also be given for passphrase"
            )
        cipher_obj = _lib.EVP_get_cipherbyname(_byte_string(cipher))
        if cipher_obj == _ffi.NULL:
            raise ValueError("Invalid cipher name")
    else:
        cipher_obj = _ffi.NULL

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        result_code = _lib.PEM_write_bio_PrivateKey(
            bio,
            pkey._pkey,
            cipher_obj,
            _ffi.NULL,
            0,
            helper.callback,
            helper.callback_args,
        )
        helper.raise_if_problem()
    elif type == FILETYPE_ASN1:
        result_code = _lib.i2d_PrivateKey_bio(bio, pkey._pkey)
    elif type == FILETYPE_TEXT:
        if _lib.EVP_PKEY_id(pkey._pkey) != _lib.EVP_PKEY_RSA:
            raise TypeError("Only RSA keys are supported for FILETYPE_TEXT")

        rsa = _ffi.gc(_lib.EVP_PKEY_get1_RSA(pkey._pkey), _lib.RSA_free)
        result_code = _lib.RSA_print(bio, rsa, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or "
            "FILETYPE_TEXT"
        )

    _openssl_assert(result_code != 0)

    return _bio_to_string(bio)



class Typing:
    """
    Provides type constants or utility methods.
    """
    CRL_REASONS: typing.ClassVar[list[bytes]] = [
        b"unspecified",
        b"keyCompromise",
        b"CACompromise",
        b"affiliationChanged",
        b"superseded",
        b"cessationOfOperation",
        b"certificateHold",
    ]

class Revoked:
    """
    A certificate revocation.
    """
    
    _crl_reasons: typing.ClassVar[list[bytes]] = Typing.CRL_REASONS

    def __init__(self) -> None:
        self._revoked = _ffi.gc(_lib.X509_REVOKED_new(), _lib.X509_REVOKED_free)

    def set_serial(self, hex_str: bytes) -> None:
        """
        Set the serial number formatted as a hexadecimal number encoded in ASCII.

        :param bytes hex_str: The new serial number.
        :return: ``None``
        """
        bignum_serial = _ffi.gc(_lib.BN_new(), _lib.BN_free)
        if _lib.BN_hex2bn(_ffi.new("BIGNUM**", [bignum_serial]), hex_str) == 0:
            raise ValueError("bad hex string")

        asn1_serial = _ffi.gc(_lib.BN_to_ASN1_INTEGER(bignum_serial, _ffi.NULL), _lib.ASN1_INTEGER_free)
        _lib.X509_REVOKED_set_serialNumber(self._revoked, asn1_serial)

    def get_serial(self) -> bytes:
        """
        Get the serial number formatted as a hexadecimal number encoded in ASCII.

        :return: The serial number.
        :rtype: bytes
        """
        asn1_int = _lib.X509_REVOKED_get0_serialNumber(self._revoked)
        bio = _new_mem_buf()
        if _lib.i2a_ASN1_INTEGER(bio, asn1_int) < 0:
            _raise_current_error()
        return _bio_to_string(bio)

    def _delete_reason(self) -> None:
        """
        Remove any existing reason extension.
        """
        ext_count = _lib.X509_REVOKED_get_ext_count(self._revoked)
        for i in range(ext_count):
            ext = _lib.X509_REVOKED_get_ext(self._revoked, i)
            if _lib.OBJ_obj2nid(_lib.X509_EXTENSION_get_object(ext)) == _lib.NID_crl_reason:
                _lib.X509_EXTENSION_free(ext)
                _lib.X509_REVOKED_delete_ext(self._revoked, i)
                break

    def set_reason(self, reason: typing.Optional[bytes]) -> None:
        """
        Set the reason of this revocation. Deletes the reason if `reason` is `None`.

        :param reason: The reason string or `None` to delete the reason.
        :type: bytes or NoneType
        :return: ``None``
        """
        if reason is None:
            self._delete_reason()
            return

        if not isinstance(reason, bytes):
            raise TypeError("reason must be None or a byte string")

        reason = reason.lower().replace(b" ", b"")
        if reason not in Typing.CRL_REASONS:
            raise ValueError("Invalid reason provided")

        reason_code = Typing.CRL_REASONS.index(reason)

        new_reason_ext = _ffi.gc(_lib.ASN1_ENUMERATED_new(), _lib.ASN1_ENUMERATED_free)
        if _lib.ASN1_ENUMERATED_set(new_reason_ext, reason_code) == 0:
            _raise_current_error()

        self._delete_reason()
        if _lib.X509_REVOKED_add1_ext_i2d(self._revoked, _lib.NID_crl_reason, new_reason_ext, 0, 0) != 1:
            _raise_current_error()

    def get_reason(self) -> typing.Optional[bytes]:
        """
        Get the reason of this revocation.

        :return: The reason, or `None` if there is none.
        :rtype: bytes or NoneType
        """
        ext_count = _lib.X509_REVOKED_get_ext_count(self._revoked)
        for i in range(ext_count):
            ext = _lib.X509_REVOKED_get_ext(self._revoked, i)
            if _lib.OBJ_obj2nid(_lib.X509_EXTENSION_get_object(ext)) == _lib.NID_crl_reason:
                bio = _new_mem_buf()
                if _lib.X509V3_EXT_print(bio, ext, 0, 0) == 0:
                    if _lib.M_ASN1_OCTET_STRING_print(bio, _lib.X509_EXTENSION_get_data(ext)) == 0:
                        _raise_current_error()
                return _bio_to_string(bio)
        return None

    def all_reasons(self) -> list[bytes]:
        """
        Return a list of all the supported reason strings.

        :return: A list of reason strings.
        :rtype: list of bytes
        """
        return Typing.CRL_REASONS[:]

    def set_rev_date(self, when: bytes) -> None:
        """
        Set the revocation timestamp as ASN.1 TIME.

        :param bytes when: The timestamp of the revocation.
        :return: ``None``
        """
        revocation_date = _new_asn1_time(when)
        if _lib.X509_REVOKED_set_revocationDate(self._revoked, revocation_date) != 1:
            _raise_current_error()

    def get_rev_date(self) -> typing.Optional[bytes]:
        """
        Get the revocation timestamp as ASN.1 TIME.

        :return: The timestamp of the revocation, or `None` if not set.
        :rtype: bytes or NoneType
        """
        dt = _lib.X509_REVOKED_get0_revocationDate(self._revoked)
        return _get_asn1_time(dt)

# Deprecated API
_RevokedInternal = Revoked
utils.deprecated(
    Revoked,
    __name__,
    "CRL support in pyOpenSSL is deprecated. Use the APIs in cryptography.",
    DeprecationWarning,
    name="Revoked"
)



# Define file type constants
FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
FILETYPE_TEXT = 3

_UNSPECIFIED = b""

def _openssl_assert(cond):
    if not cond:
        raise RuntimeError("OpenSSL operation failed")

def _dump_crl_internal(type, crl_obj):
    """
    Dumps the CRL into the specified format.

    :param int type: The export format, either FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_TEXT.
    :param CRL crl_obj: The CRL object to be dumped.
    :rtype: bytes
    """
    buf = _ffi.new("BIO *")
    _lib.BIO_new_fp(buf, _lib.BIO_NOCLOSE)
    
    if type == FILETYPE_PEM:
        _lib.PEM_write_bio_X509_CRL(buf, crl_obj._crl)
    elif type == FILETYPE_ASN1:
        _lib.i2d_X509_CRL_bio(buf, crl_obj._crl)
    elif type == FILETYPE_TEXT:
        # Assumed text format conversion
        ret = _lib.X509_CRL_print(buf, crl_obj._crl)
        _openssl_assert(ret == 1)
        out = _ffi.buffer(_lib.BIO_get_mem_data(buf))[:]
    else:
        raise ValueError("Unsupported type")

    out = _ffi.buffer(_lib.BIO_get_mem_data(buf))[:]
    return out

def _load_crl_internal(type, der_data):
    """
    Loads a CRL from a given format.

    :param int type: The input format, either FILETYPE_PEM or FILETYPE_ASN1.
    :param bytes der_data: The DER encoded CRL data.
    :rtype: CRL
    """
    crl = CRL()
    buf = _ffi.new("BIO *")
    _lib.BIO_new_mem_buf(der_data, len(der_data))
    
    if type == FILETYPE_PEM:
        _lib.PEM_read_bio_X509_CRL(buf, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        _lib.d2i_X509_CRL_bio(buf, _ffi.NULL)
    else:
        raise ValueError("Unsupported type")

    return crl

def _new_asn1_time(timestamp):
    """
    Creates a new ASN.1 TIME object from a timestamp string.

    :param bytes timestamp: A timestamp formatted as ASN.1 TIME (YYYYMMDDhhmmssZ).
    :rtype: ASN1_TIME
    """
    asn1_time = _lib.ASN1_TIME_new()
    _openssl_assert(asn1_time != _ffi.NULL)
    _lib.ASN1_TIME_set_string(asn1_time, timestamp)
    return asn1_time

class CRL:
    """
    A certificate revocation list.
    """

    def __init__(self) -> None:
        crl = _lib.X509_CRL_new()
        self._crl = _ffi.gc(crl, _lib.X509_CRL_free)

    def to_cryptography(self) -> x509.CertificateRevocationList:
        """
        Export as a ``cryptography`` CRL.

        :rtype: ``cryptography.x509.CertificateRevocationList``
        """
        from cryptography.x509 import load_der_x509_crl

        der = _dump_crl_internal(FILETYPE_ASN1, self)
        return load_der_x509_crl(der)


    @classmethod
    def from_cryptography(
        cls, crypto_crl: x509.CertificateRevocationList
    ) -> 'CRL':
        """
        Construct based on a ``cryptography`` *crypto_crl*.

        :param crypto_crl: A ``cryptography`` certificate revocation list
        :type crypto_crl: ``cryptography.x509.CertificateRevocationList``

        :rtype: CRL
        """
        if not isinstance(crypto_crl, x509.CertificateRevocationList):
            raise TypeError("Must be a certificate revocation list")

        der = crypto_crl.public_bytes(Encoding.DER)
        return _load_crl_internal(FILETYPE_ASN1, der)

    def get_revoked(self) -> tuple['_RevokedInternal', ...] | None:
        """
        Return the revocations in this certificate revocation list.

        :return: The revocations in this CRL.
        :rtype: :class:`tuple` of :class:`Revocation`
        """
        results = []
        revoked_stack = _lib.X509_CRL_get_REVOKED(self._crl)
        num_revoked = _lib.sk_X509_REVOKED_num(revoked_stack)
        for i in range(num_revoked):
            revoked = _lib.sk_X509_REVOKED_value(revoked_stack, i)
            revoked_copy = _lib.X509_REVOKED_dup(revoked)
            pyrev = _RevokedInternal.__new__(_RevokedInternal)
            pyrev._revoked = _ffi.gc(revoked_copy, _lib.X509_REVOKED_free)
            results.append(pyrev)
        return tuple(results) if results else None

    def add_revoked(self, revoked: '_RevokedInternal') -> None:
        """
        Add a revoked entry to the CRL structure.

        :param _RevokedInternal revoked: The new revocation.
        :return: ``None``
        """
        copy = _lib.X509_REVOKED_dup(revoked._revoked)
        _openssl_assert(copy != _ffi.NULL)

        add_result = _lib.X509_CRL_add0_revoked(self._crl, copy)
        _openssl_assert(add_result != 0)

    def get_issuer(self) -> 'X509':
        """
        Get the CRL's issuer.

        :rtype: X509Name
        """
        _issuer = _lib.X509_NAME_dup(_lib.X509_CRL_get_issuer(self._crl))
        _openssl_assert(_issuer != _ffi.NULL)
        _issuer = _ffi.gc(_issuer, _lib.X509_NAME_free)
        issuer = X509.__new__(X509)
        issuer._name = _issuer
        return issuer

    def set_version(self, version: int) -> None:
        """
        Set the CRL version.

        :param int version: The version of the CRL.
        :return: ``None``
        """
        _openssl_assert(_lib.X509_CRL_set_version(self._crl, version) != 0)

    def set_lastUpdate(self, when: bytes) -> None:
        """
        Set when the CRL was last updated.

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        lastUpdate = _new_asn1_time(when)
        ret = _lib.X509_CRL_set1_lastUpdate(self._crl, lastUpdate)
        _openssl_assert(ret == 1)

    
# Define file type constants
FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
FILETYPE_TEXT = 3

_UNSPECIFIED = b""

def _openssl_assert(cond):
    if not cond:
        raise RuntimeError("OpenSSL operation failed")

def _dump_crl_internal(type, crl_obj):
    """
    Dumps the CRL into the specified format.

    :param int type: The export format, either FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_TEXT.
    :param CRL crl_obj: The CRL object to be dumped.
    :rtype: bytes
    """
    buf = _lib.BIO_new(_lib.BIO_s_mem())
    if type == FILETYPE_PEM:
        _lib.PEM_write_bio_X509_CRL(buf, crl_obj._crl)
    elif type == FILETYPE_ASN1:
        _lib.i2d_X509_CRL_bio(buf, crl_obj._crl)
    elif type == FILETYPE_TEXT:
        ret = _lib.X509_CRL_print(buf, crl_obj._crl)
        _openssl_assert(ret == 1)
    else:
        raise ValueError("Unsupported type")

    out = _ffi.buffer(_lib.BIO_get_mem_data(buf))[:]
    _lib.BIO_free(buf)
    return out

def _load_crl_internal(type, der_data):
    """
    Loads a CRL from a given format.

    :param int type: The input format, either FILETYPE_PEM or FILETYPE_ASN1.
    :param bytes der_data: The DER encoded CRL data.
    :rtype: CRL
    """
    crl = CRL()
    buf = _ffi.new("BIO *")
    _lib.BIO_new_mem_buf(der_data, len(der_data))
    
    if type == FILETYPE_PEM:
        _lib.PEM_read_bio_X509_CRL(buf, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        _lib.d2i_X509_CRL_bio(buf, _ffi.NULL)
    else:
        raise ValueError("Unsupported type")

    return crl

def _new_asn1_time(timestamp):
    """
    Creates a new ASN.1 TIME object from a timestamp string.

    :param bytes timestamp: A timestamp formatted as ASN.1 TIME (YYYYMMDDhhmmssZ).
    :rtype: ASN1_TIME
    """
    asn1_time = _lib.ASN1_TIME_new()
    _openssl_assert(asn1_time != _ffi.NULL)
    _lib.ASN1_TIME_set_string(asn1_time, timestamp)
    return asn1_time

class CRL:
    """
    A certificate revocation list.
    """

    def __init__(self) -> None:
        crl = _lib.X509_CRL_new()
        self._crl = _ffi.gc(crl, _lib.X509_CRL_free)

    def to_cryptography(self) -> x509.CertificateRevocationList:
        """
        Export as a ``cryptography`` CRL.

        :rtype: ``cryptography.x509.CertificateRevocationList``
        """
        from cryptography.x509 import load_der_x509_crl

        der = _dump_crl_internal(FILETYPE_ASN1, self)
        return load_der_x509_crl(der)

    @classmethod
    def from_cryptography(
        cls, crypto_crl: x509.CertificateRevocationList
    ) -> 'CRL':
        """
        Construct based on a ``cryptography`` *crypto_crl*.

        :param crypto_crl: A ``cryptography`` certificate revocation list
        :type crypto_crl: ``cryptography.x509.CertificateRevocationList``

        :rtype: CRL
        """
        if not isinstance(crypto_crl, x509.CertificateRevocationList):
            raise TypeError("Must be a certificate revocation list")

        der = crypto_crl.public_bytes(Encoding.DER)
        return _load_crl_internal(FILETYPE_ASN1, der)

    def get_revoked(self) -> tuple['_RevokedInternal', ...] | None:
        """
        Return the revocations in this certificate revocation list.

        :return: The revocations in this CRL.
        :rtype: :class:`tuple` of :class:`Revocation`
        """
        results = []
        revoked_stack = _lib.X509_CRL_get_REVOKED(self._crl)
        num_revoked = _lib.sk_X509_REVOKED_num(revoked_stack)
        for i in range(num_revoked):
            revoked = _lib.sk_X509_REVOKED_value(revoked_stack, i)
            revoked_copy = _lib.X509_REVOKED_dup(revoked)
            pyrev = _RevokedInternal.__new__(_RevokedInternal)
            pyrev._revoked = _ffi.gc(revoked_copy, _lib.X509_REVOKED_free)
            results.append(pyrev)
        return tuple(results) if results else None

    def add_revoked(self, revoked: '_RevokedInternal') -> None:
        """
        Add a revoked entry to the CRL structure.

        :param _RevokedInternal revoked: The new revocation.
        :return: ``None``
        """
        copy = _lib.X509_REVOKED_dup(revoked._revoked)
        _openssl_assert(copy != _ffi.NULL)

        add_result = _lib.X509_CRL_add0_revoked(self._crl, copy)
        _openssl_assert(add_result != 0)

    def get_issuer(self) -> 'X509':
        """
        Get the CRL's issuer.

        :rtype: X509Name
        """
        _issuer = _lib.X509_NAME_dup(_lib.X509_CRL_get_issuer(self._crl))
        _openssl_assert(_issuer != _ffi.NULL)
        _issuer = _ffi.gc(_issuer, _lib.X509_NAME_free)
        issuer = X509.__new__(X509)
        issuer._name = _issuer
        return issuer

    def set_version(self, version: int) -> None:
        """
        Set the CRL version.

        :param int version: The version of the CRL.
        :return: ``None``
        """
        _openssl_assert(_lib.X509_CRL_set_version(self._crl, version) != 0)

    def set_lastUpdate(self, when: bytes) -> None:
        """
        Set when the CRL was last updated.

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        lastUpdate = _new_asn1_time(when)
        ret = _lib.X509_CRL_set1_lastUpdate(self._crl, lastUpdate)
        _openssl_assert(ret == 1)

    def set_nextUpdate(self, when: bytes) -> None:
        """
        Set when the CRL will next be updated.

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        nextUpdate = _new_asn1_time(when)
        ret = _lib.X509_CRL_set1_nextUpdate(self._crl, nextUpdate)
        _openssl_assert(ret == 1)

    def sign(self, issuer_cert: 'X509', issuer_key: 'PKey', digest: bytes) -> None:
        """
        Sign the CRL.

        :param X509 issuer_cert: The issuer's certificate.
        :param PKey issuer_key: The issuer's private key.
        :param bytes digest: The digest method to sign the CRL with.
        """
        digest_obj = _lib.EVP_get_digestbyname(digest)
        _openssl_assert(digest_obj != _ffi.NULL)
        _lib.X509_CRL_set_issuer_name(
            self._crl, _lib.X509_get_subject_name(issuer_cert._x509)
        )
        _lib.X509_CRL_sort(self._crl)
        result = _lib.X509_CRL_sign(self._crl, issuer_key._pkey, digest_obj)
        _openssl_assert(result != 0)

    def export(
        self,
        cert: 'X509',
        key: 'PKey',
        type: int = FILETYPE_PEM,
        days: int = 100,
        digest: bytes = _UNSPECIFIED
    ) -> bytes:
        """
        Export the CRL as a string.

        :param X509 cert: The certificate used to sign the CRL.
        :param PKey key: The key used to sign the CRL.
        :param int type: The export format, either FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_TEXT.
        :param int days: The number of days until the next update of this CRL.
        :param bytes digest: The name of the message digest to use (e.g., ``b"sha256"``).
        :rtype: bytes
        """
        if not isinstance(cert, X509):
            raise TypeError("cert must be an X509 instance")
        if not isinstance(key, PKey):
            raise TypeError("key must be a PKey instance")
        if not isinstance(type, int):
            raise TypeError("type must be an integer")
        if digest == _UNSPECIFIED:
            raise TypeError("digest must be provided")

        digest_obj = _lib.EVP_get_digestbyname(digest)
        if digest_obj == _ffi.NULL:
            raise ValueError("No such digest method")

        sometime = _lib.ASN1_TIME_new()
        _openssl_assert(sometime != _ffi.NULL)
        sometime = _ffi.gc(sometime, _lib.ASN1_TIME_free)

        # Set last update time
        _lib.X509_gmtime_adj(sometime, 0)
        _lib.X509_CRL_set1_lastUpdate(self._crl, sometime)

        # Set next update time
        _lib.X509_gmtime_adj(sometime, days * 24 * 60 * 60)
        _lib.X509_CRL_set1_nextUpdate(self._crl, sometime)

        # Set issuer name
        _lib.X509_CRL_set_issuer_name(
            self._crl, _lib.X509_get_subject_name(cert._x509)
        )

        # Sign the CRL
        if not _lib.X509_CRL_sign(self._crl, key._pkey, digest_obj):
            _raise_current_error()

        return _dump_crl_internal(type, self)




def _dump_crl_internal(type, crl_obj):
    """
    Dumps the CRL into the specified format.

    :param int type: The export format, either :data:`FILETYPE_PEM`,
        :data:`FILETYPE_ASN1`, or :data:`FILETYPE_TEXT`.
    :param CRL crl_obj: The CRL object to be dumped.
    :rtype: bytes
    """
    if type == FILETYPE_PEM:
        buf = _ffi.new("BIO *")
        _lib.BIO_new_fp(buf, _lib.BIO_NOCLOSE)
        _lib.PEM_write_bio_X509_CRL(buf, crl_obj._crl)
        out = _ffi.buffer(_lib.BIO_get_mem_data(buf))[:]
    elif type == FILETYPE_ASN1:
        buf = _ffi.new("BIO *")
        _lib.BIO_new_fp(buf, _lib.BIO_NOCLOSE)
        _lib.i2d_X509_CRL_bio(buf, crl_obj._crl)
        out = _ffi.buffer(_lib.BIO_get_mem_data(buf))[:]
    elif type == FILETYPE_TEXT:
        # Assuming text format requires a different method or conversion
        out = _lib.X509_CRL_print(crl_obj._crl).decode('utf-8')
    else:
        raise ValueError("Unsupported type")

    return out



class _PassphraseHelper:
    def __init__(
        self,
        type: int,
        passphrase: PassphraseCallableT | None,
        more_args: bool = False,
        truncate: bool = False,
    ) -> None:
        if type != FILETYPE_PEM and passphrase is not None:
            raise ValueError(
                "only FILETYPE_PEM key format supports encryption"
            )
        self._passphrase = passphrase
        self._more_args = more_args
        self._truncate = truncate
        self._problems: list[Exception] = []

    @property
    def callback(self) -> Any:
        if self._passphrase is None:
            return _ffi.NULL
        elif isinstance(self._passphrase, bytes) or callable(self._passphrase):
            return _ffi.callback("pem_password_cb", self._read_passphrase)
        else:
            raise TypeError(
                "Last argument must be a byte string or a callable."
            )

    @property
    def callback_args(self) -> Any:
        if self._passphrase is None:
            return _ffi.NULL
        elif isinstance(self._passphrase, bytes) or callable(self._passphrase):
            return _ffi.NULL
        else:
            raise TypeError(
                "Last argument must be a byte string or a callable."
            )

    def raise_if_problem(self, exceptionType: type[Exception] = Error) -> None:
        if self._problems:
            # Flush the OpenSSL error queue
            try:
                _exception_from_error_queue(exceptionType)
            except exceptionType:
                pass

            raise self._problems.pop(0)

    def _read_passphrase(
        self, buf: Any, size: int, rwflag: Any, userdata: Any
    ) -> int:
        try:
            if callable(self._passphrase):
                if self._more_args:
                    result = self._passphrase(size, rwflag, userdata)
                else:
                    result = self._passphrase(rwflag)
            else:
                assert self._passphrase is not None
                result = self._passphrase
            if not isinstance(result, bytes):
                raise ValueError("Bytes expected")
            if len(result) > size:
                if self._truncate:
                    result = result[:size]
                else:
                    raise ValueError(
                        "passphrase returned by callback is too long"
                    )
            for i in range(len(result)):
                buf[i] = result[i : i + 1]
            return len(result)
        except Exception as e:
            self._problems.append(e)
            return 0


def load_publickey(type: int, buffer: str | bytes) -> PKey:
    """
    Load a public key from a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM`,
        :data:`FILETYPE_ASN1`).
    :param buffer: The buffer the key is stored in.
    :type buffer: A Python string object, either unicode or bytestring.
    :return: The PKey object.
    :rtype: :class:`PKey`
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    if type == FILETYPE_PEM:
        evp_pkey = _lib.PEM_read_bio_PUBKEY(
            bio, _ffi.NULL, _ffi.NULL, _ffi.NULL
        )
    elif type == FILETYPE_ASN1:
        evp_pkey = _lib.d2i_PUBKEY_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if evp_pkey == _ffi.NULL:
        _raise_current_error()

    pkey = PKey.__new__(PKey)
    pkey._pkey = _ffi.gc(evp_pkey, _lib.EVP_PKEY_free)
    pkey._only_public = True
    return pkey


def load_privatekey(
    type: int,
    buffer: str | bytes,
    passphrase: PassphraseCallableT | None = None,
) -> PKey:
    """
    Load a private key (PKey) from the string *buffer* encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the key is stored in
    :param passphrase: (optional) if encrypted PEM format, this can be
                       either the passphrase to use, or a callback for
                       providing the passphrase.

    :return: The PKey object
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        evp_pkey = _lib.PEM_read_bio_PrivateKey(
            bio, _ffi.NULL, helper.callback, helper.callback_args
        )
        helper.raise_if_problem()
    elif type == FILETYPE_ASN1:
        evp_pkey = _lib.d2i_PrivateKey_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if evp_pkey == _ffi.NULL:
        _raise_current_error()

    pkey = PKey.__new__(PKey)
    pkey._pkey = _ffi.gc(evp_pkey, _lib.EVP_PKEY_free)
    return pkey


