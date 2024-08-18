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



def dump_certificate_request(type: int, req: X509Req) -> bytes:
    """
    Dump the certificate request *req* into a buffer string encoded with the
    type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param req: The certificate request to dump
    :return: The buffer with the dumped certificate request in
    """
    bio = _new_mem_buf()

    if type == FILETYPE_PEM:
        result_code = _lib.PEM_write_bio_X509_REQ(bio, req._req)
    elif type == FILETYPE_ASN1:
        result_code = _lib.i2d_X509_REQ_bio(bio, req._req)
    elif type == FILETYPE_TEXT:
        result_code = _lib.X509_REQ_print_ex(bio, req._req, 0, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or "
            "FILETYPE_TEXT"
        )

    _openssl_assert(result_code != 0)

    return _bio_to_string(bio)


_dump_certificate_request_internal = dump_certificate_request

utils.deprecated(
    dump_certificate_request,
    __name__,
    (
        "CSR support in pyOpenSSL is deprecated. You should use the APIs "
        "in cryptography."
    ),
    DeprecationWarning,
    name="dump_certificate_request",
)



# Constants
FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
FILETYPE_TEXT = 3

class _X509ReqInternal:
    def __init__(self):
        self._req = None

class MODE_AUTO:
    pass

class MODE_MMAP_EXT:
    pass

class MODE_FILE:
    pass

class MODE_MEMORY:
    pass

class MODE_FD:
    pass

class IO(IOBase):
    def read(self) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        pass

class ConnectionPlugin:
    def __init__(self, name: str, description: str, author: str, output: Any, optiondict: dict):
        self.name = name
        self.description = description
        self.author = author
        self.output = output
        self.optiondict = optiondict

    def consume_packet(self, packet: Any) -> None:
        pass

    def produce_packets(self) -> List[Any]:
        return []

    def flush(self) -> None:
        pass

class tabulate:
    @staticmethod
    def tabulate(rows: List[List[Any]], headers: List[str]) -> str:
        return "\n".join([",".join(row) for row in rows])

class faulthandler:
    @staticmethod
    def enable() -> None:
        pass

def configure_output_modules(kwargs: dict) -> None:
    # Configuration logic for output modules
    pass

def configure_plugin_options(kwargs: dict) -> None:
    # Configuration logic for plugin options
    pass

def get_inputs(kwargs: dict) -> List[str]:
    # Input retrieval logic
    return []

def process_files(inputs: List[str], **kwargs) -> None:
    # File processing logic
    pass

# Optimized functions
def load_certificate_request(type: int, buffer: bytes) -> _X509ReqInternal:
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)
    req = None
    if type == FILETYPE_PEM:
        req = _lib.PEM_read_bio_X509_REQ(bio, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        req = _lib.d2i_X509_REQ_bio(bio, _ffi.NULL)
    else:
        raise ValueError("Invalid type argument")

    if req == _ffi.NULL:
        _raise_current_error()

    x509req = _X509ReqInternal()
    x509req._req = _ffi.gc(req, _lib.X509_REQ_free)
    return x509req

def sign(pkey: Any, data: Union[str, bytes], digest: str) -> bytes:
    data = _text_to_bytes_and_warn("data", data)
    digest_obj = _lib.EVP_get_digestbyname(_byte_string(digest))
    if digest_obj == _ffi.NULL:
        raise ValueError("No such digest method")

    md_ctx = _lib.EVP_MD_CTX_new()
    md_ctx = _ffi.gc(md_ctx, _lib.EVP_MD_CTX_free)
    _lib.EVP_SignInit(md_ctx, digest_obj)
    _lib.EVP_SignUpdate(md_ctx, data, len(data))

    length = _lib.EVP_PKEY_size(pkey._pkey)
    if length <= 0:
        raise ValueError("Invalid key size")
    signature_buffer = _ffi.new("unsigned char[]", length)
    signature_length = _ffi.new("unsigned int *")
    final_result = _lib.EVP_SignFinal(md_ctx, signature_buffer, signature_length, pkey._pkey)
    if final_result != 1:
        _raise_current_error()

    return _ffi.buffer(signature_buffer, signature_length[0])[:]

def verify(cert: Any, signature: bytes, data: Union[str, bytes], digest: str) -> None:
    data = _text_to_bytes_and_warn("data", data)
    digest_obj = _lib.EVP_get_digestbyname(_byte_string(digest))
    if digest_obj == _ffi.NULL:
        raise ValueError("No such digest method")

    pkey = _lib.X509_get_pubkey(cert._x509)
    if pkey == _ffi.NULL:
        _raise_current_error()
    pkey = _ffi.gc(pkey, _lib.EVP_PKEY_free)

    md_ctx = _lib.EVP_MD_CTX_new()
    md_ctx = _ffi.gc(md_ctx, _lib.EVP_MD_CTX_free)
    _lib.EVP_VerifyInit(md_ctx, digest_obj)
    _lib.EVP_VerifyUpdate(md_ctx, data, len(data))
    verify_result = _lib.EVP_VerifyFinal(md_ctx, signature, len(signature), pkey)
    if verify_result != 1:
        _raise_current_error()

def dump_crl(type: int, crl: Any) -> bytes:
    bio = _new_mem_buf()
    ret = None
    if type == FILETYPE_PEM:
        ret = _lib.PEM_write_bio_X509_CRL(bio, crl._crl)
    elif type == FILETYPE_ASN1:
        ret = _lib.i2d_X509_CRL_bio(bio, crl._crl)
    elif type == FILETYPE_TEXT:
        ret = _lib.X509_CRL_print(bio, crl._crl)
    else:
        raise ValueError("Invalid type argument")

    if ret != 1:
        _raise_current_error()

    return _bio_to_string(bio)



# Definitions for constants and functions assumed to be in your codebase
FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
_CRLError = ValueError  # Assuming this as a placeholder

def _new_mem_buf(buffer: bytes) -> Any:
    # Dummy implementation
    pass

def _raise_current_error() -> None:
    # Dummy implementation
    raise _CRLError("Error occurred")

def _CRLInternal() -> 'CRL':
    # Dummy implementation of _CRLInternal class
    class CRL:
        def __init__(self):
            self._crl = None
    return CRL()

def load_crl(type: int, buffer: Union[str, bytes]) -> Any:
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)
    crl = None
    if type == FILETYPE_PEM:
        crl = _lib.PEM_read_bio_X509_CRL(bio, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        crl = _lib.d2i_X509_CRL_bio(bio, _ffi.NULL)
    else:
        raise ValueError("Invalid type argument")

    if crl == _ffi.NULL:
        _raise_current_error()

    result = _CRLInternal()
    result._crl = _ffi.gc(crl, _lib.X509_CRL_free)
    return result

def decompress_file(filepath: str, extension: str, unzipdir: str) -> List[str]:
    openfiles = []
    try:
        if extension == '.gz':
            openfiles.append(gzip.open(filepath, 'rb'))
        elif extension == '.bz2':
            openfiles.append(bz2.open(filepath, 'rb'))
        elif extension == '.zip':
            pswd = getpass.getpass(f"Enter password for .zip file {filepath!r} [default: none]: ").encode()
            with zipfile.ZipFile(filepath) as z:
                openfiles.extend(z.open(z2, 'r', pswd) for z2 in z.namelist())
    except (RuntimeError, zipfile.BadZipFile) as e:
        logger.error(f"Could not process .zip file {filepath!r}. {e}")
        return []

    tempfiles = []
    for openfile in openfiles:
        with openfile:
            try:
                openfile.peek(1)  # Check if file is readable
                with tempfile.NamedTemporaryFile(dir=unzipdir, delete=False, prefix=os.path.basename(filepath)) as tfile:
                    tfile.write(openfile.read())
                    tempfiles.append(tfile.name)
            except OSError as e:
                logger.error(f"Could not process compressed file {filepath!r}. {e}")
    return tempfiles

def print_plugins(plugins: dict) -> None:
    headers = ['module', 'name', 'title', 'type', 'author', 'description']
    rows = [
        [module.__module__, name, module.name, module.__class__.__bases__[0].__name__,
         module.author, module.description]
        for name, module in sorted(plugins.items())
    ]
    print(tabulate.tabulate(rows, headers=headers))

def main(plugin_args=None, **kwargs) -> None:
    global plugin_chain
    if not plugin_args:
        plugin_args = {}

    faulthandler.enable()

    if not plugin_chain:
        logger.error("No plugin selected")
        sys.exit(1)

    plugin_chain[0].defrag_ip = kwargs.get("defrag", False)
    setup_logging(kwargs)
    configure_output_modules(kwargs)
    configure_plugin_options(kwargs)
    inputs = get_inputs(kwargs)
    process_files(inputs, **kwargs)

def setup_logging(kwargs: dict) -> None:
    log_format = "%(levelname)s (%(name)s) - %(message)s"
    log_level = logging.DEBUG if kwargs.get("debug", False) else \
                logging.INFO if kwargs.get("verbose", False) else \
                logging.CRITICAL if kwargs.get("quiet", False) else logging.WARNING
    logging.basicConfig(format=log_format, level=log_level)
    logging.getLogger("pypacker").setLevel(logging.CRITICAL)
    if kwargs.get("allcc", False):
        logging.getLogger().setLevel(logging.DEBUG)



# Set up logger
logger = logging.getLogger(__name__)

def process_plugins(parser: dshell.core.DshellArgumentParser, opts, plugin_map: dict, active_plugins: OrderedDict):
    """Process and load plugins based on user input."""
    if opts.plugin:
        plugins = {plugin.strip() for plugin in '+'.join(opts.plugin).split('+') if plugin.strip()}
        for plugin in plugins:
            if plugin not in plugin_map:
                continue
            plugin_module = import_module(plugin_map[plugin])
            plugin_name = plugin
            # Ensure unique plugin names
            while plugin_name in active_plugins:
                plugin_name = f"{plugin}{len(active_plugins) + 1}"
            active_plugins[plugin_name] = plugin_module.DshellPlugin()
            plugin_chain.append(active_plugins[plugin_name])
            parser.add_plugin_arguments(plugin_name, active_plugins[plugin_name])

def display_help_and_exit(parser: dshell.core.DshellArgumentParser, plugin_chain):
    """Print help messages and exit."""
    parser.print_help()
    print("\n".join(f"############### {plugin.name}\n{plugin.longdescription}\nDefault BPF: \"{plugin.bpf}\"" for plugin in plugin_chain))
    sys.exit()

def display_plugins_and_exit():
    """List all available plugins and exit."""
    try:
        print_plugins(get_plugin_information())
    except ImportError as e:
        logger.error(e, exc_info=True)
    sys.exit()

def display_output_modules_and_exit():
    """List available output modules and exit."""
    output_map = get_output_modules(get_output_path())
    for modulename in sorted(output_map):
        try:
            module = import_module(f"dshell.output.{modulename}").obj
            print(f"\t{modulename:<25} {module._DESCRIPTION}")
        except Exception as e:
            logger.debug(f"Could not load {modulename} module. ({e.__class__.__name__}: {e})")
    sys.exit()

def configure_argument_parser() -> dshell.core.DshellArgumentParser:
    """Configure and return the argument parser."""
    parser = dshell.core.DshellArgumentParser(
        usage="%(prog)s [options] [plugin options] file1 file2 ... fileN",
        add_help=False
    )
    parser.add_argument('-h', '-?', '--help', dest='help', action='store_true', default=False, help="Print common command-line flags and exit")
    parser.add_argument('--version', action='version', version=f"Dshell {dshell_version}")
    parser.add_argument('-d', '-p', '--plugin', dest='plugin', type=str, action='append', metavar="PLUGIN", help="Use a specific plugin module")
    parser.add_argument('--ebpf', default='', type=str, metavar="BPF", help="Extend existing BPFs with provided input for additional filtering")
    parser.add_argument('-i', '--interface', help="Listen live on INTERFACE instead of reading pcap")
    parser.add_argument('-l', '--ls', '--list', action="store_true", dest='list', help='List all available plugins')
    parser.add_argument("--lo", "--list-output", action="store_true", help="List available output modules")
    parser.add_argument("--cbf", "--color-blind-friendly", action="store_true", help="Activate color blind friendly mode")
    parser.add_argument("-o", "--omodule", type=str, metavar="MODULE", help="Use specified output module for plugins instead of defaults")
    parser.add_argument('files', nargs='*', help="pcap files or globs to process")
    return parser

def main_command_line():
    global plugin_chain
    plugin_chain = []

    plugin_map = get_plugins()
    active_plugins = OrderedDict()
    parser = configure_argument_parser()

    opts, xopts = parser.parse_known_args()
    process_plugins(parser, opts, plugin_map, active_plugins)

    if xopts:
        for xopt in xopts:
            logger.warning(f'Could not understand argument {xopt!r}')

    if opts.help:
        display_help_and_exit(parser, plugin_chain)

    if opts.list:
        display_plugins_and_exit()

    if opts.listoutput:
        display_output_modules_and_exit()

    if not opts.plugin:
        parser.epilog = "Select a plugin to use with -d or --plugin"
        parser.print_help()
        sys.exit()

    if not opts.files and not opts.interface:
        parser.epilog = "Include a pcap file or an interface to get started. Use --help for more information."
        parser.print_help()
        sys.exit()

    # Prepare arguments for plugins
    plugin_args = {plugin_name: {darg: getattr(opts, darg) for darg, dattr in parser.get_plugin_arguments(plugin_name, plugin)}
                   for plugin_name, plugin in active_plugins.items()}

    # Call the main processing function with prepared arguments
    main(plugin_args=plugin_args, **vars(opts))

if __name__ == "__main__":
    main_command_line()



class DshellArgumentParser(argparse.ArgumentParser):

    def add_plugin_arguments(self, plugin_name, plugin_obj):
        """
        Adds plugin-specific arguments to the parser.
        """
        optiondict = plugin_obj.optiondict
        if optiondict:
            group = self.add_argument_group(f'{plugin_obj.name} plugin options')
            for argname, optargs in optiondict.items():
                optname = f"{plugin_name}_{argname}"
                optargs['type'] = custom_bytes if optargs.get('type') == bytes else optargs.get('type')
                if 'default' in optargs and optargs.get('type') == custom_bytes:
                    optargs['default'] = custom_bytes(optargs['default'])
                group.add_argument(f"--{optname}", dest=optname, **optargs)

    def get_plugin_arguments(self, plugin_name, plugin_obj):
        """
        Returns a list of argument names and their associated attributes.
        """
        optiondict = plugin_obj.optiondict
        return [(f"{plugin_name}_{argname}", argname) for argname in optiondict] if optiondict else []

logger = logging.getLogger(__name__)

def get_plugins():
    """
    Generate a list of all available plugin modules.
    """
    plugins = {}
    import_base = get_plugin_path().split(os.path.sep)[:-1]
    plugin_path = get_plugin_path()

    # Scan local plugin modules
    for root, _, files in os.walk(plugin_path):
        if '__init__.py' in files:
            import_path = root.split(os.path.sep)[len(import_base):]
            for f in iglob(os.path.join(root, "*.py")):
                name = os.path.splitext(os.path.basename(f))[0]
                if name != '__init__':
                    if name in plugins:
                        logger.warning(f"Duplicate plugin name found: {name}")
                    module = '.'.join(["dshell"] + import_path + [name])
                    plugins[name] = module

    # Discover additional external plugins
    for ep_plugin in pkg_resources.iter_entry_points(group="dshell_plugins"):
        if ep_plugin.name in plugins:
            logger.warning(f"Duplicate plugin name found: {ep_plugin.name}")
        plugins[ep_plugin.name] = ep_plugin.module_name

    return plugins

def get_output_modules(output_module_path):
    """
    Generate a list of all available output modules.
    """
    return [
        os.path.splitext(os.path.basename(f))[0]
        for f in iglob(os.path.join(output_module_path, "*.py"))
        if os.path.splitext(os.path.basename(f))[0] not in {'__init__', 'output'}
    ]

class DTP(pypacker.Packet):
    __hdr__ = (
        ("v", "B", 0),
        ("tvs", None, triggerlist.TriggerList)
    )

    @staticmethod
    def _dissect_tvs(collect_tvs=True):
        def dissect_tvs_sub(buf):
            off, tvs = 0, []
            while off < len(buf):
                _, hlen = unpack(buf[off: off + 4])
                if collect_tvs:
                    tvs.append(DTP.TV(buf[off: off + hlen]))
                off += hlen
            return tvs if collect_tvs else off
        return dissect_tvs_sub

    def _dissect(self, buf):
        off_tvs = 1
        dissect_tvs_sub = DTP._dissect_tvs(collect_tvs=False)
        tvlen = dissect_tvs_sub(buf[off_tvs:])
        self.tvs(buf[off_tvs: off_tvs + tvlen], DTP._dissect_tvs())
        return off_tvs + tvlen

    class TV(pypacker.Packet):
        __hdr__ = (
            ("t", "H", 0),
            ("len", "H", 0)
        )

class DNS(pypacker.Packet):
    __hdr__ = (
        ("id", "H", 0x1234),
        ("flags", "H", DNS_AD | DNS_RD),
        ("questions_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
        ("answers_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
        ("authrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
        ("addrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
        ("queries", None, triggerlist.TriggerList),
        ("answers", None, triggerlist.TriggerList),
        ("auths", None, triggerlist.TriggerList),
        ("addrecords", None, triggerlist.TriggerList)
    )

    def _dissect(self, buf):
        off = 12
        amounts = unpack(buf[4:12])
        dissect_methods = [
            (DNS._dissect_queries, 'queries'),
            (DNS._dissect_answers, 'answers'),
            (DNS._dissect_authserver, 'auths'),
            (DNS._dissect_addreq, 'addrecords')
        ]

        for dissect_method, attr_name in dissect_methods:
            length = dissect_method(amounts.pop(0), collect_queries=attr_name == 'queries')(buf[off:])
            setattr(self, attr_name, getattr(self, f'{attr_name}_tvs')(buf[off: off + length]))
            off += length

        return off

    @staticmethod
    def get_dns_length(bts):
        off = 0
        while off < len(bts):
            if bts[off] & 0xC0:
                return off + 2
            if bts[off] == 0x00:
                return off + 1
            off += bts[off] + 1
        return 0

    @staticmethod
    def _dissect_queries(amount, collect_queries=True):
        def dissect_queries_sub(buf):
            off, queries = 0, []
            while amount > 0 and off < len(buf):
                q_end = off + DNS.get_dns_length(buf[off:]) + 4
                if collect_queries:
                    queries.append(DNS.Query(buf[off: q_end]))
                off = q_end
                amount -= 1
            return queries if collect_queries else off
        return dissect_queries_sub

    @staticmethod
    def _dissect_answers(amount, collect_answers=True):
        def dissect_answers_sub(buf):
            off, answers = 0, []
            while amount > 0 and off < len(buf):
                a_end = off + DNS.get_dns_length(buf[off:]) + 8
                dlen = unpack_H(buf[a_end: a_end + 2])[0]
                a_end += 2 + dlen
                if collect_answers:
                    answers.append(DNS.Answer(buf[off: a_end]))
                off = a_end
                amount -= 1
            return answers if collect_answers else off
        return dissect_answers_sub

    @staticmethod
    def _dissect_authserver(amount, collect_authserver=True):
        def dissect_authserver_sub(buf):
            off, authserver = 0, []
            while amount > 0 and off < len(buf):
                a_end = off + DNS.get_dns_length(buf[off:]) + 8
                dlen = unpack_H(buf[a_end: a_end + 2])[0]
                a_end += 2 + dlen
                if collect_authserver:
                    authserver.append(DNS.Auth(buf[off: a_end]))
                off = a_end
                amount -= 1
            return authserver if collect_authserver else off
        return dissect_authserver_sub

    @staticmethod
    def _dissect_addreq(amount, collect_addreq=True):
        def dissect_addreq_sub(buf):
            off, addrecords = 0, []
            while amount > 0 and off < len(buf):
                if buf[off: off + 3] == b"\x00\x00\x29":
                    if collect_addreq:
                        addrecords.append(DNS.AddRecordRoot(buf[off: off + 11]))
                    off += 11
                else:
                    dlen = unpack_H(buf[off + 10: off + 12])[0]
                    if collect_addreq:
                        addrecords.append(DNS.AddRecord(buf[off: off + 12 + dlen]))
                    off += 12 + dlen
                amount -= 1
            return addrecords if collect_addreq else off
        return dissect_addreq_sub

    def _update_fields(self):
        if self._header_value_changed:
            for attr in ['questions_amount', 'answers_amount', 'authrr_amount', 'addrr_amount']:
                if getattr(self, f'{attr}_au_active'):
                    setattr(self, attr, len(getattr(self, attr.replace('amount', 'queries'))))

            if any(tl._cached_bin is None for tl in [self.queries, self.answers, self.auths, self.addrecords]):
                ref_bts = self.header_bytes[:12]
                for tl in [self.queries, self.answers, self.auths, self.addrecords]:
                    for idx, tl_element in enumerate(tl):
                        if isinstance(tl_element, tuple(DNS.TYPES_COMPRESSABLE)):
                            tl_element.compress(ref_bts)
                        ref_bts += tl.entry_to_bytes(idx)

class custom_bytes:
    # Example implementation; modify as needed
    def __init__(self, value):
        self.value



"""
Checksum logic for various protocols.
"""

# Setup logging
logger = logging.getLogger("pypacker")

# Performance optimizations
array_array = array.array
ntohs = socket.ntohs
ENDIANNESS_IS_BIG = sys.byteorder == "big"

# TCP and UDP checksum functions
def in_cksum_add(s, buf):
    buflen = len(buf)
    a = array_array("H", buf[:buflen & ~0x1])

    if ENDIANNESS_IS_BIG:
        a.byteswap()

    if buflen & 0x1:
        a.append(unpack("<H", buf[-1:] + b"\x00")[0])

    return s + sum(a)

def in_cksum_done(s):
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ntohs((~s) & 0xFFFF)

# Checksum library loading
def try_load_native_lib():
    for libname in ["checksum_native_x86_64", "checksum_native_arm_32", "checksum_native_arm_64"]:
        libpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "native", f"{libname}.so")
        logger.debug("Trying to load C-based checksum implementation %s", libname)
        try:
            chksumlib = ctypes.cdll.LoadLibrary(libpath)
            in_chksum_c = chksumlib.in_chksum
            in_chksum_c.restype = ctypes.c_uint32
            in_chksum_c.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_uint32)
            in_chksum_c(b"0123", 4)
            return in_chksum_c
        except Exception:
            continue
    raise RuntimeError("No suitable C-based checksum implementation found.")

try:
    in_cksum = try_load_native_lib()
    logger.debug("Using native checksum implementation")
except Exception as ex:
    logger.debug(ex)
    logger.debug("Using Python checksum implementation")
    in_cksum = lambda bts: in_cksum_done(in_cksum_add(0, bts))

# CRC-32C Checksum Table (simplified representation)
crc32c_table = [ ... ]  # Assume the table is defined correctly

# ColorOutput class
class ColorOutput(Output):
    _DESCRIPTION = "Reconstructed output with ANSI color codes"
    _PACKET_FORMAT = """Packet %(counter)s (%(proto)s)
Start: %(ts)s
%(sip)16s:%(sport)6s -> %(dip)16s:%(dport)6s (%(bytes)s bytes)

%(data)s

"""
    _CONNECTION_FORMAT = """Connection %(counter)s (%(protocol)s)
Start: %(starttime)s
End:   %(endtime)s
%(clientip)16s:%(clientport)6s -> %(serverip)16s:%(serverport)6s (%(clientbytes)s bytes)
%(serverip)16s:%(serverport)6s -> %(clientip)16s:%(clientport)6s (%(serverbytes)s bytes)

%(data)s

"""
    _DEFAULT_FORMAT = _PACKET_FORMAT
    _DEFAULT_DELIM = "\n\n"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 1
        self.colors = {'cs': '31', 'sc': '32', '--': '34'}
        self.hexmode = kwargs.get('hex', False)
        self.format_is_set = False

    def setup(self):
        """Activate color blind friendly mode."""
        if self.cbf:
            self.colors['cs'] = '33'

    def write(self, *args, **kwargs):
        if not self.format_is_set:
            format_str = self._CONNECTION_FORMAT if 'clientip' in kwargs else self._PACKET_FORMAT
            self.set_format(format_str)
            self.format_is_set = True

        colorformat = "\x1b[%sm%s\x1b[0m"
        rawdata = self._collect_raw_data(args, kwargs)
        cleanup_func = dshell.util.hex_plus_ascii if self.hexmode else dshell.util.printable_text
        rawdata = [(cleanup_func(data), direction) for data, direction in rawdata]
        data = [colorformat % (self.colors.get(direction, '0'), data) for data, direction in rawdata]
        super().write(counter=self.counter, *data, **kwargs)
        self.counter += 1

    def _collect_raw_data(self, args, kwargs):
        rawdata = []
        for arg in args:
            if isinstance(arg, dshell.core.Blob):
                if arg.data:
                    rawdata.append((arg.data, arg.direction))
            elif isinstance(arg, dshell.core.Connection):
                for blob in arg.blobs:
                    if blob.data:
                        rawdata.append((blob.data, blob.direction))
            elif isinstance(arg, dshell.core.Packet):
                rawdata.append((arg.pkt.body_bytes, kwargs.get('direction', '--')))
            elif isinstance(arg, tuple):
                rawdata.append(arg)
            else:
                rawdata.append((arg, kwargs.get('direction', '--')))
        return rawdata

# Diameter class
class Diameter(pypacker.Packet):
    __hdr__ = (
        ("v", "B", 1),
        ("len", "3s", b"\x00" * 3),
        ("flags", "B", 0),
        ("cmd", "3s", b"\x00" * 3),
        ("app_id", "I", 0),
        ("hop_id", "I", 0),
        ("end_id", "I", 0),
        ("avps", None, triggerlist.TriggerList)
    )

    def _dissect(self, buf):
        self.avps(buf[20:], Diameter._parse_avps)
        return len(buf)

    class AVP(pypacker.Packet):
        __hdr__ = (
            ("code", "I", 0),
            ("flags", "B", 0),
            ("len", "3s", b""),
        )

    @staticmethod
    def _parse_avps(buf):
        avps = []
        off = 0
        while off < len(buf):
            avplen = int.from_bytes(buf[off + 5: off + 8], "big")
            avplen = ((avplen + 3) // 4) * 4
            avps.append(Diameter.AVP(buf[off: off + avplen]))
            off += avplen
        return avps

# DNS Plugin class
class DshellPlugin(dnsplugin.DNSPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(
            name="DNS",
            description="Extract and summarize DNS queries and responses",
            longdescription="""
The DNS plugin extracts and summarizes DNS queries and their responses. If
possible, each query is paired with its response(s).

Possible anomalies can be found using the --dns_show_noanswer,
--dns_only_noanswer, --dns_show_norequest, or --dns_only_norequest flags
(see --help).
""",
            author="bg/twp",
            bpf="udp and port 53",
            output=AlertOutput(label=__name__),
            optiondict={'show_noanswer': {'action': 'store_true', 'help': 'report unanswered queries alongside other queries'},
                        'show_norequest': {'action': 'store_true', 'help': 'report unsolicited responses alongside other responses'},
                        'only_noanswer': {'action': 'store_true', 'help': 'report only unanswered queries'},
                        'only_norequest': {'action': 'store_true', 'help': 'report only unsolicited responses'},
                        'country': {'action': 'store_true', 'help': 'show country code for returned IP addresses'},
                        'asn': {'action': 'store_true', 'help': 'show ASN for returned IP addresses'},
                    }
        )

    def premodule(self):
        self.show_norequest |= self.only_norequest
        self.show_noanswer |= self.only_noanswer

    def dns_handler(self, conn, requests, responses):
        if (self.only_norequest and requests) or (self.only_noanswer and responses):
            return
        if not self.show_norequest and not requests:
            return
        if not self.show_noanswer and not responses:
            return

        msg = []
        if requests:
            request_pkt = requests[-1]
            request = request_pkt.pkt.highest_layer
            for query in request.queries:
                msg.append(f"{query.type}? {query.name_s}")

        # Further processing of responses can be added here

        # Example of how to use msg
        print("\n".join(msg))
"""Encapsulated Security Protocol."""

from pypacker import pypacker


class ESP(pypacker.Packet):
	__hdr__ = (
		("spi", "I", 0),
		("seq", "I", 0)
	)

"""
Ethernet II, IEEE 802.3

RFC 1042
"""
import logging

from pypacker.layer12 import lldp, slac
from pypacker import pypacker, triggerlist
from pypacker.pypacker import FIELD_FLAG_IS_TYPEFIELD
from pypacker.structcbs import unpack_H

from pypacker.layer12 import arp, dtp, pppoe, flow_control, lacp
from pypacker.layer3 import ip, ip6, ipx
from pypacker.layer567 import ptpv2

logger = logging.getLogger("pypacker")

ETH_CRC_LEN	= 4
ETH_HDR_LEN	= 14

ETH_LEN_MIN	= 64		# minimum frame length with CRC
ETH_LEN_MAX	= 1518		# maximum frame length with CRC

ETH_MTU		= ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN
ETH_MIN		= ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_PUP		= 0x0200		# PUP protocol
ETH_TYPE_IP		= 0x0800		# IPv4 protocol
ETH_TYPE_ARP		= 0x0806		# address resolution protocol
ETH_TYPE_WOL		= 0x0842		# Wake on LAN
ETH_TYPE_CDP		= 0x2000		# Cisco Discovery Protocol
ETH_TYPE_DTP		= 0x2004		# Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP		= 0x8035		# reverse addr resolution protocol
ETH_TYPE_ETHTALK	= 0x809B		# Apple Talk
ETH_TYPE_AARP		= 0x80F3		# Appletalk Address Resolution Protocol
ETH_TYPE_8021Q		= 0x8100		# IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX		= 0x8137		# Internetwork Packet Exchange
ETH_TYPE_NOV		= 0x8138		# Novell
ETH_TYPE_IP6		= 0x86DD		# IPv6 protocol
ETH_TYPE_MPLS_UCAST	= 0x8847		# MPLS unicast
ETH_TYPE_MPLS_MCAST	= 0x8848		# MPLS multicast
ETH_TYPE_PPOE_DISC	= 0x8863		# PPPoE Discovery
ETH_TYPE_PPOE_SESS	= 0x8864		# PPPoE Session
ETH_TYPE_JUMBOF		= 0x8870		# Jumbo Frames
ETH_TYPE_PROFINET	= 0x8892		# Realtime-Ethernet PROFINET
ETH_TYPE_ATAOE		= 0x88A2		# ATA other Ethernet
ETH_TYPE_ETHERCAT	= 0x88A4		# Realtime-Ethernet Ethercat
ETH_TYPE_PBRIDGE	= 0x88A8		# Provider Bridging IEEE 802.1ad
ETH_TYPE_POWERLINK	= 0x88AB		# Realtime Ethernet POWERLINK
ETH_TYPE_LLDP		= 0x88CC		# Link Layer Discovery Protocol
ETH_TYPE_SERCOS		= 0x88CD		# Realtime Ethernet SERCOS III
ETH_TYPE_PTPV2		= 0x88F7		# PTPv2 IEEE 1588-2008
ETH_TYPE_FIBRE_ETH	= 0x8906		# Fibre Channel over Ethernet
ETH_TYPE_FCOE		= 0x8914		# FCoE Initialization Protocol (FIP)
ETH_TYPE_TUNNELING	= 0x9100		# Provider Bridging IEEE 802.1QInQ 2007
ETH_TYPE_EFC		= 0x8808		# Ethernet flow control
ETH_TYPE_SP		= 0x8809		# Slow Protocols
ETH_TYPE_SLAC		= 0x88E1		# SLAC


# MPLS label stack fields
MPLS_LABEL_MASK		= 0xFFFFF000
MPLS_QOS_MASK		= 0x00000E00
MPLS_TTL_MASK		= 0x000000FF
MPLS_LABEL_SHIFT	= 12
MPLS_QOS_SHIFT		= 9
MPLS_TTL_SHIFT		= 0
MPLS_STACK_BOTTOM	= 0x0100


# Standard or double vlan tag
# ETH_TYPE_TUNNELING as outer tag is NON-standard!
# see: https://en.wikipedia.org/wiki/IEEE_802.1ad
VLAN_TAG_START = {ETH_TYPE_8021Q, ETH_TYPE_PBRIDGE, ETH_TYPE_TUNNELING}


class Ethernet(pypacker.Packet):
	__hdr__ = [
		("dst", "6s", b"\xff" * 6),
		("src", "6s", b"\xff" * 6),
		("vlan", None, triggerlist.TriggerList),
		("type", "H", ETH_TYPE_IP, FIELD_FLAG_IS_TYPEFIELD),
		[("padding", b"")]
	]

	dst_s = pypacker.get_property_mac("dst")
	src_s = pypacker.get_property_mac("src")
	type_t = pypacker.get_property_translator("type", "ETH_TYPE_")

	__handler__ = {
		ETH_TYPE_IP: ip.IP,
		ETH_TYPE_ARP: arp.ARP,
		ETH_TYPE_DTP: dtp.DTP,
		ETH_TYPE_IPX: ipx.IPX,
		ETH_TYPE_IP6: ip6.IP6,
		ETH_TYPE_PPOE_DISC: pppoe.PPPoE,
		ETH_TYPE_PPOE_SESS: pppoe.PPPoE,
		ETH_TYPE_PTPV2: ptpv2.PTPv2,
		ETH_TYPE_EFC: flow_control.FlowControl,
		ETH_TYPE_LLDP: lldp.LLDP,
		ETH_TYPE_SP: lacp.LACP,
		ETH_TYPE_SLAC: slac.Slac
	}

	class Dot1Q(pypacker.Packet):
		__hdr__ = (
			("type", "H", ETH_TYPE_8021Q),
			("tci", "H", 0)  # tag control information PCP(3 bits),CFI(1 bit), VID(12 bits)
		)

		def __get_prio(self):
			return (self.tci & 0xE000) >> 13

		def __set_prio(self, value):
			self.tci = (self.tci & ~0xE000) | (value << 13)
		prio = property(__get_prio, __set_prio)

		def __get_cfi(self):
			return (self.tci & 0x1000) >> 12

		def __set_cfi(self, value):
			self.tci = (self.tci & ~0x1000) | (value << 12)
		cfi = property(__get_cfi, __set_cfi)

		def __get_vid(self):
			return self.tci & 0x0FFF

		def __set_vid(self, value):
			self.tci = self.tci & 0xF000 | value
		vid = property(__get_vid, __set_vid)

		type_t = pypacker.get_property_translator("type", "ETH_TYPE_")

	def _dissect(self, buf):
		hlen = 14
		# Ethernet formats:
		# RFC 894 (Ethernet II) -> type = -> value >1500
		# 802.[2,3] (LLC format) -> type = length field -> value <=1500, not supported
		eth_type = unpack_H(buf[hlen - 2: hlen])[0]

		# Any VLAN tag present? in this case: type field is actually a vlan tag
		if eth_type in VLAN_TAG_START:
			if eth_type == ETH_TYPE_8021Q:
				#logger.debug("VLAN: ETH_TYPE_8021Q")
				self.vlan(buf[12: 16], lambda tval: Ethernet.Dot1Q(tval))
				hlen += 4
				# Get real higher layer type
				eth_type = unpack_H(buf[16: 18])[0]
			# 802.1ad: support up to 2 tags (double tagging aka QinQ)
			else:
				#logger.debug("VLAN: 802.1ad")
				self.vlan(buf[12: 20], lambda tval: [Ethernet.Dot1Q(tval[0: 4]), Ethernet.Dot1Q(tval[4: 8])])
				hlen += 8
				# Get real higher layer type
				eth_type = unpack_H(buf[20: 22])[0]

		#logger.debug("eth type is: %d" % eth_type)

		# Handle ethernet-padding: remove it but save for later use.
		# Don't use headers for this because this is a rare situation.
		dlen = len(buf) - hlen  # data length, "may" include padding

		# Ethernet packets with less than the minimum 64 bytes (header + all upper layer data + FCS) are padded to 64 bytes.
		# Ethernet won't give us the real data vs. padding length so assume everything at "the border" of 60 bytes is padded
		# and check this by analyzing the higher layer data-ength info.
		# Note: creates unneeded checks if there is no padding (total data length is 60 "by accident").
		if len(buf) <= 60:
			try:
				# This will only work on complete headers: Ethernet + IP + ...
				# Handle padding using IPv4, IPv6 etc (min size "eth + ..." = 60 bytes)
				#logger.debug("Checking for padding, dlen: %d < 46" % dlen)
				if eth_type == ETH_TYPE_IP:
					#logger.debug("Padding: ETH_TYPE_IP")
					dlen_ip = unpack_H(buf[hlen + 2: hlen + 4])[0]  # Real data length

					if dlen_ip < dlen:
						# Padding found
						self.padding = buf[hlen + dlen_ip:].tobytes()
						#logger.debug("Got padding for (ip total length=%d): %r" % (dlen_ip, self.padding))
						dlen = dlen_ip
				# Handle padding using IPv6
				# IPv6 is a piece of sh$§! payloadlength (in header) = exclusive standard header
				# but INCLUSIVE options!
				elif eth_type == ETH_TYPE_IP6:
					#logger.debug("Padding: ETH_TYPE_IP6")
					dlen_ip = unpack_H(buf[hlen + 4: hlen + 6])[0]  # Real data length
					# logger.debug("eth.hlen=%d, data length based on header: %d" % (hlen, dlen_ip))

					if 40 + dlen_ip < dlen:
						# Padding found
						self.padding = buf[hlen + 40 + dlen_ip:].tobytes()
						#logger.debug("Got padding for IPv6: %r" % self.padding)
						dlen = 40 + dlen_ip
				elif eth_type == ETH_TYPE_LLDP:
					#logger.debug("Padding: ETH_TYPE_LLDP")
					# This is a bit redundant as we re-parse TLV when accessing the LLDP layer
					dlen_lldp, _ = lldp.count_and_dissect_tlvs(buf[hlen:], onlylen=True)
					self.padding = buf[hlen + dlen_lldp:].tobytes()
					dlen = dlen_lldp
				elif eth_type == ETH_TYPE_SP:
					#logger.debug("Padding: ETH_TYPE_SP")
					lacppdu_len = 110
					self.padding = buf[hlen + lacppdu_len:].tobytes()
					dlen = lacppdu_len
			except:
				# Could not extract padding info, assuming incomplete ethernet frame.
				# Init of handler will take place after all.
				pass
		#logger.debug("len(buf)=%d, hlen=%d, len(higher)=%d" % (len(buf), hlen, dlen))
		#logger.debug("Upper layer bytes will be: %r" % buf[hlen: hlen + dlen].tobytes())
		return hlen, eth_type, buf[hlen: hlen + dlen]

	def _update_fields(self):
		self._update_higherlayer_id()

	def bin(self, update_auto_fields=True):
		# Padding needs to be placed at the very end
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields) + self.padding

	def __len__(self):
		return super().__len__() + len(self.padding)

	def direction(self, other):
		#logger.debug("checking direction: %s<->%s" % (self, other))
		if self.dst == other.dst and self.src == other.src:
			# Consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		if (self.dst == other.src and self.src == other.dst) or\
			(self.dst == b"\xff\xff\xff\xff\xff\xff" and other.dst == self.src):  # broadcast
			return pypacker.Packet.DIR_REV
		return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.dst, self.src = self.src, self.dst
"""Ethernet Flow Control"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import pack_H, unpack_H

logger = logging.getLogger("pypacker")

PAUSE_OPCODE	= 0x0001		# Pause frame IEEE 802.3x
PFC_OPCODE	= 0x0101		# Priority Flow Control IEEE 802.1Qbb


class FlowControl(pypacker.Packet):
	__hdr__ = (
		("opcode", "H", PAUSE_OPCODE),
	)

	def _dissect(self, buf):
		if buf[:2] == b"\x01\x01":
			ul_type = PFC_OPCODE
		else:
			ul_type = PAUSE_OPCODE
		return 2, ul_type

	class Pause(pypacker.Packet):
		__hdr__ = (
			("ptime", "H", 0x0000),
		)

	class PFC(pypacker.Packet):
		__hdr__ = (
			("ms", "B", 0),  # Most significant octet is reserved,set to zero
			("ls", "B", 0),  # Least significant octet indicates time_vector parameter
			("time", None, triggerlist.TriggerList),
		)

		# Conveniant access to ls field(bit representation via list)
		# e.g. 221 -> [1, 1, 0, 1, 1, 1, 0, 1]
		def _get_ls(self):
			#return [(self.ls >> x) & 1 for x in reversed(range(8))]
			return [int(bstr) for bstr in bin(self.ls)[2:]]

		# e.g. [1, 1, 0, 1, 1, 1, 0, 1] -> 221
		def _set_ls(self, value):
			#self.ls = int("".join(map(str, value)), 2)
			self.ls = int("".join(["%d" % bint for bint in value]), 2)
		ls_list = property(_get_ls, _set_ls)

		# Conveniant access to time field (decimal representation via list)
		def _get_time(self):
			return [unpack_H(x)[0] for x in self.time]

		def _set_time(self, value):
			self.time = [pack_H(x) for x in value]
		time_list = property(_get_time, _set_time)

		@staticmethod
		def _get_times(buf):
			times = []
			for i in range(0, 16, 2):
				times.append(buf[i:i + 2].tobytes())
			return times

		def _dissect(self, buf):
			#logger.debug("Buf for PFC: %r" % buf.tobytes())
			self.time(buf[2:], FlowControl.PFC._get_times)
			return len(buf)

	__handler__ = {
		PAUSE_OPCODE: Pause,
		PFC_OPCODE: PFC
	}


####################################################################
#
#
#           DSHELL A THROUGH D SCRIPTS END
#
#
###################################################################



####################################################################
#
#
#           DSHELL E THROUGH F SCRIPTS START
#
#
###################################################################

"""
This output module converts plugin output into JSON and indexes it into
an Elasticsearch datastore

NOTE: This module requires the third-party 'elasticsearch' Python module
"""

class ElasticOutput(dshell.output.jsonout.JSONOutput):
    """
    Elasticsearch output module
    Use with --output=elasticsearchout

    It is recommended that it be run with some options set:
        host:       server hosting the database (localhost)
        port:       HTTP port listening (9200)
        index:      name of index storing results ("dshell")
        type:       the type for each alert ("alerts")

    Example use:
        decode --output=elasticout --oargs="index=dshellalerts" --oargs="type=netflowout" -d netflow ~/pcap/example.pcap
    """

    _DESCRIPTION = "Automatically insert data into an elasticsearch instance"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs.copy())

        self.options = {}
        self.options['host'] = kwargs.get('host', 'localhost')
        self.options['port'] = int(kwargs.get('port', 9200))
        self.options['index'] = kwargs.get('index', 'dshell')
        self.options['type'] = kwargs.get('type', 'alerts')

        self.es = Elasticsearch([self.options['host']], port=self.options['port'])

    def write(self, *args, **kwargs):
        "Converts alert's keyword args to JSON and indexes it into Elasticsearch datastore."
        if args and 'data' not in kwargs:
            kwargs['data'] = self.delimiter.join(map(str, args))

        # Elasticsearch can't handle IPv6 (at time of writing)
        # Just delete the ints and expand the string notation.
        # Hopefully, it will be possible to perform range searches on this
        # consistent IP string format.
        try:
            del kwargs['dipint']
        except KeyError:
            pass
        try:
            del kwargs['sipint']
        except KeyError:
            pass
        try:
            kwargs['dip'] = ipaddress.ip_address(kwargs['dip']).exploded
        except KeyError:
            pass
        try:
            kwargs['sip'] = ipaddress.ip_address(kwargs['sip']).exploded
        except KeyError:
            pass

        jsondata = json.dumps(kwargs, ensure_ascii=self.ensure_ascii, default=self.json_default)
#        from pprint import pprint
#        pprint(jsondata)
        self.es.index(index=self.options['index'], doc_type=self.options['type'], body=jsondata)

obj = ElasticOutput


"""
Generates color-coded Screen/HTML output similar to Wireshark Follow Stream
"""

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="Followstream",
            author="amm/dev195",
            description="Generates color-coded Screen/HTML output similar to Wireshark Follow Stream. Empty connections will be skipped.",
            bpf="tcp",
            output=ColorOutput(label=__name__),
        )

    def connection_handler(self, conn):
        if conn.totalbytes > 0:
            self.write(conn, **conn.info())
            return conn

if __name__ == "__main__":
    print(DshellPlugin())
"""
Errors
======

"""


class GeoIP2Error(RuntimeError):
    """There was a generic error in GeoIP2.

    This class represents a generic error. It extends :py:exc:`RuntimeError`
    and does not add any additional attributes.

    """


class AddressNotFoundError(GeoIP2Error):
    """The address you were looking up was not found.

    .. attribute:: ip_address

      The IP address used in the lookup. This is only available for database
      lookups.

      :type: str

    .. attribute:: network

      The network associated with the error. In particular, this is the
      largest network where no address would be found. This is only
      available for database lookups.

      :type: ipaddress.IPv4Network or ipaddress.IPv6Network

    """

    ip_address: Optional[str]
    _prefix_len: Optional[int]

    def __init__(
        self,
        message: str,
        ip_address: Optional[str] = None,
        prefix_len: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.ip_address = ip_address
        self._prefix_len = prefix_len

    @property
    def network(self) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """The network for the error"""

        if self.ip_address is None or self._prefix_len is None:
            return None
        return ipaddress.ip_network(f"{self.ip_address}/{self._prefix_len}", False)


class AuthenticationError(GeoIP2Error):
    """There was a problem authenticating the request."""


class HTTPError(GeoIP2Error):
    """There was an error when making your HTTP request.

    This class represents an HTTP transport error. It extends
    :py:exc:`GeoIP2Error` and adds attributes of its own.

    :ivar http_status: The HTTP status code returned
    :ivar uri: The URI queried
    :ivar decoded_content: The decoded response content

    """

    def __init__(
        self,
        message: str,
        http_status: Optional[int] = None,
        uri: Optional[str] = None,
        decoded_content: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.uri = uri
        self.decoded_content = decoded_content


class InvalidRequestError(GeoIP2Error):
    """The request was invalid."""


class OutOfQueriesError(GeoIP2Error):
    """Your account is out of funds for the service queried."""


class PermissionRequiredError(GeoIP2Error):
    """Your account does not have permission to access this service."""
"""
Goes through TCP connections and tries to find FTP control channels and
associated data channels. Optionally, it will write out any file data it
sees into a separate directory.

If a data connection is seen, it prints a message indicating the user, pass,
and file requested. If the --ftp_dump flag is set, it also dumps the file into the
--ftp_outdir directory.
"""

# constants for channel type
CTRL_CONN = 0
DATA_CONN = 1

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="ftp",
            description="alerts on FTP traffic and, optionally, rips files",
            longdescription="""
Goes through TCP connections and tries to find FTP control channels and
associated data channels. Optionally, it will write out any file data it
sees into a separate directory.

If a data connection is seen, it prints a message indicating the user, pass,
and file requested. If the --ftp_dump flag is set, it also dumps the file into the
--ftp_outdir directory.
""",
            author="amm,dev195",
            bpf="tcp",
            output=AlertOutput(label=__name__),
            optiondict={
                "ports": {
                    'help': 'comma-separated list of ports to watch for control connections (default: 21)',
                    'metavar': 'PORT,PORT,PORT,[...]',
                    'default': '21'},
                "dump": {
                    'action': 'store_true',
                    'help': 'dump files from stream'},
                "outdir": {
                    'help': 'directory to write output files (default: "ftpout")',
                    'metavar': 'DIRECTORY',
                    'default': 'ftpout'}
            }
        )

    def __update_bpf(self):
        """
        Dynamically change the BPF to allow processing of data transfer
        channels.
        """
        dynfilters = []
        for conn, metadata in self.conns.items():
            try:
                dynfilters += ["(host %s and host %s)" % metadata["tempippair"]]
            except (KeyError, TypeError):
                continue
        for a, p in self.data_channel_map.keys():
            dynfilters += ["(host %s and port %d)" % (a, p)]
        self.bpf = "(%s) and ((%s)%s)" % (
            self.original_bpf,
            " or ".join( "port %d" % p for p in self.control_ports ),
            " or " + " or ".join(dynfilters) if dynfilters else ""
        )
        self.recompile_bpf()

    def premodule(self):
        # dictionary containing metadata for connections
        self.conns = {}
        # dictionary mapping data channels (host, port) to their control channels
        self.data_channel_map = {}
        # ports used for control channels
        self.control_ports = set()
        # Original BPF without manipulation
        self.original_bpf = self.bpf
        # set control ports using user-provided info
        for p in self.ports.split(','):
            try:
                self.control_ports.add(int(p))
            except ValueError as e:
                self.error("{!r} is not a valid port. Skipping.".format(p))
        if not self.control_ports:
            self.error("Could not find any control ports. At least one must be set for this plugin.")
            sys.exit(1)

        # create output directory
        # break if it cannot be created
        if self.dump and not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except (IOError, OSError) as e:
                self.error("Could not create output directory: {!r}: {!s}"
                           .format(self.outdir, e))
                sys.exit(1)

    def connection_init_handler(self, conn):
        # Create metadata containers for any new connections
        if conn.serverport in self.control_ports:
            self.conns[conn.addr] = {
                'mode': CTRL_CONN,
                'user': '',
                'pass': '',
                'path': [],
                'datachan': None,
                'lastcommand': '',
                'tempippair': None,
                'filedata': None,
                'file': ['', '', '']
            }
        elif self.dump and (conn.clientip, conn.clientport) in self.data_channel_map:
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': self.data_channel_map[(conn.clientip, conn.clientport)],
                'filedata': None
            }
        elif self.dump and (conn.serverip, conn.serverport) in self.data_channel_map:
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': self.data_channel_map[(conn.serverip, conn.serverport)],
                'filedata': None
            }
        elif self.dump:
            # This is a data connection with an unknown control connection. It
            # may be a passive mode transfer without known port info, yet.
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': None,
                'filedata': None
            }

    def connection_close_handler(self, conn):
        # After data channel closes, store file content in control channel's
        # 'filedata' field.
        # Control channel will write it to disk after it determines the
        # filename.
        try:
            info = self.conns[conn.addr]
        except KeyError:
            return

        if self.dump and info['mode'] == DATA_CONN:
            # find the associated control channel
            if info['ctrlchan'] == None:
                if (conn.clientip, conn.clientport) in self.data_channel_map:
                    info['ctrlchan'] = self.data_channel_map[(conn.clientip, conn.clientport)]
                if (conn.serverip, conn.serverport) in self.data_channel_map:
                    info['ctrlchan'] = self.data_channel_map[(conn.serverip, conn.serverport)]
            try:
                ctrlchan = self.conns[info['ctrlchan']]
            except KeyError:
                return
            # add data to control channel dictionary
            for blob in conn.blobs:
                if ctrlchan['filedata']:
                    ctrlchan['filedata'] += blob.data
                else:
                    ctrlchan['filedata'] = blob.data
            # update port list and data channel knowledge
            if (conn.serverip, conn.serverport) == ctrlchan['datachan']:
                del self.data_channel_map[ctrlchan['datachan']]
                ctrlchan['datachan'] = None
                self.__update_bpf()
            if (conn.clientip, conn.clientport) == ctrlchan['datachan']:
                del self.data_channel_map[ctrlchan['datachan']]
                ctrlchan['datachan'] = None
                self.__update_bpf()
            del self.conns[conn.addr]

        elif info['mode'] == CTRL_CONN:
            # clear control channels if they've been alerted on
            if info['file'] == None:
                del self.conns[conn.addr]

    def postmodule(self):
        for addr, info in self.conns.items():
            if self.dump and 'filedata' in info and info['filedata']:
                origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                outname = dshell.util.gen_local_filename(self.outdir, origname)
                with open(outname, 'wb') as fh:
                    fh.write(info['filedata'])
                numbytes = len(info['filedata'])
                info['filedata'] = None
                info['outfile'] = outname
                msg = 'User: %s, Pass: %s, %s File: %s (Incomplete: %d bytes written to %s)' % (info['user'], info['pass'], info['file'][0], os.path.join(*info['file'][1:3]), numbytes, os.path.basename(outname))
                self.write(msg, **info)


    def blob_handler(self, conn, blob):
        try:
            info = self.conns[conn.addr]
        except KeyError:
            # connection was not initialized correctly
            # set the blob to hidden and move on
            blob.hidden = True
            return

        if info['mode'] == DATA_CONN:
            return conn, blob

        try:
            data = blob.data
            data = data.decode('ascii')
        except UnicodeDecodeError as e:
            # Could not convert command data to readable ASCII
            blob.hidden = True
            return

        if blob.direction == 'cs':
            # client-to-server: try and get the command issued
            if ' ' not in data.rstrip():
                command = data.rstrip()
                param = ''
            else:
                command, param = data.rstrip().split(' ', 1)
            command = command.upper()
            info['lastcommand'] = command

            if command == 'USER':
                info['user'] = param

            elif command == 'PASS':
                info['pass'] = param

            elif command == 'CWD':
                info['path'].append(param)

            elif command == 'PASV' or command == 'EPSV':
                if self.dump:
                    # Temporarily store the pair of IP addresses
                    # to open up the BPF filter until blob_handler processes
                    # the response with the full IP/Port information.
                    # Note: Due to the way blob processing works, we don't
                    # get this information until after the data channel is
                    # established.
                    info['tempippair'] = tuple(
                        sorted((conn.clientip, conn.serverip))
                    )
                    self.__update_bpf()

            # For file transfers (including LIST), store tuple
            # (Direction, Path, Filename) in info['file']
            elif command == 'LIST':
                if param == '':
                    info['file'] = (
                        'RETR', os.path.normpath(os.path.join(*info['path']))
                        if len(info['path'])
                        else '', 'LIST'
                    )
                else:
                    info['file'] = (
                        'RETR', os.path.normpath(os.path.join(os.path.join(*info['path']), param))
                        if len(info['path'])
                        else '', 'LIST'
                    )
            elif command == 'RETR':
                info['file'] = (
                    'RETR', os.path.normpath(os.path.join(*info['path']))
                    if len(info['path'])
                    else '', param
                )
            elif command == 'STOR':
                info['file'] = (
                    'STOR', os.path.normpath(os.path.join(*info['path']))
                    if len(info['path'])
                    else '', param
                )

        # Responses
        else:
            # Rollback directory change unless 2xx response
            if info['lastcommand'] == 'CWD' and data[0] != '2':
                info['path'].pop()
            # Write out files upon resonse to transfer commands
            if info['lastcommand'] in ('LIST', 'RETR', 'STOR'):
                if self.dump and info['filedata']:
                    origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                    outname = dshell.util.gen_local_filename(self.outdir, origname)
                    with open(outname, 'wb') as fh:
                        fh.write(info['filedata'])
                    numbytes = len(info['filedata'])
                    info['filedata'] = None
                    info['outfile'] = outname
                    info.update(conn.info())
                    msg = 'User: "{}", Pass: "{}", {} File: {} ({:,} bytes written to {})'.format(
                        info['user'],
                        info['pass'],
                        info['file'][0],
                        os.path.join(*info['file'][1:3]),
                        numbytes,
                        os.path.basename(outname)
                    )
                else:
                    info.update(conn.info())
                    msg = 'User: "{}", Pass: "{}", {} File: {}'.format(
                        info['user'],
                        info['pass'],
                        info['file'][0],
                        os.path.join(*info['file'][1:3])
                    )
                    if data[0] not in ('1','2'):
                        msg += ' ({})'.format(data.rstrip())
                info['ts'] = blob.ts
                if (blob.sip == conn.sip):
                    self.write(msg, **info, dir_arrow="->")
                else:
                    self.write(msg, **info, dir_arrow="<-")
                info['file'] = None

            # Handle EPSV mode port setting
            if info['lastcommand'] == 'EPSV' and data[0] == '2':
                ret = re.findall('\(\|\|\|\d+\|\)', data)
                # TODO delimiters other than pipes
                if ret:
                    tport = int(ret[0].split('|')[3])
                    info['datachan'] = (conn.serverip, tport)
                    if self.dump:
                        self.data_channel_map[(conn.serverip, tport)] = conn.addr
                        info['tempippair'] = None
                        self.__update_bpf()

        # Look for ip/port information, assuming PSV response
        ret = re.findall('\d+,\d+,\d+,\d+,\d+\,\d+', data)
        if len(ret) == 1:
            tip, tport = self.calculateTransfer(ret[0])    # transfer ip, transfer port
            info['datachan'] = (tip, tport)                 # Update this control channel's knowledge of currently working data channel
            if self.dump:
                self.data_channel_map[(tip,tport)] = conn.addr     # Update plugin's global datachan knowledge
                info['tempippair'] = None
                self.__update_bpf()

        return conn, blob


    def calculateTransfer(self, val):
        # calculate passive FTP data port
        tmp = val.split(',')
        ip = '.'.join(tmp[:4])
        port = int(tmp[4])*256 + int(tmp[5])
        return ip, port


if __name__ == "__main__":
    print(DshellPlugin())



####################################################################
#
#
#           DSHELL E THROUGH F SCRIPTS END
#
#
###################################################################


####################################################################
#
#
#           DSHELL H SCRIPTS START
#
#
###################################################################


"""Cisco Hot Standby Router Protocol."""


# Opcodes
HELLO = 0
COUP = 1
RESIGN = 2

# States
INITIAL = 0x00
LEARN = 0x01
LISTEN = 0x02
SPEAK = 0x04
STANDBY = 0x08
ACTIVE = 0x10


class HSRP(pypacker.Packet):
	__hdr__ = (
		("version", "B", 0),
		("opcode", "B", 0),
		("state", "B", 0),
		("hello", "B", 0),
		("hold", "B", 0),
		("priority", "B", 0),
		("group", "B", 0),
		("rsvd", "B", 0),
		("auth", "8s", b"cisco"),
		("vip", "4s", b"")
	)
"""
Generates packet or reconstructed stream output as a HTML page.

Based on colorout module originally written by amm
"""

from dshell.output.output import Output
import dshell.util
import dshell.core
from xml.sax.saxutils import escape

class HTMLOutput(Output):
    _DESCRIPTION = "HTML format output"
    _PACKET_FORMAT = """<h1>Packet %(counter)s (%(protocol)s)</h1><h2>Start: %(ts)s
%(sip)s:%(sport)s -> %(dip)s:%(dport)s (%(bytes)s bytes)
</h2>
%(data)s
"""
    _CONNECTION_FORMAT = """<h1>Connection %(counter)s (%(protocol)s)</h1><h2>Start: %(starttime)s
End: %(endtime)s
%(clientip)s:%(clientport)s -> %(serverip)s:%(serverport)s (%(clientbytes)s bytes)
%(serverip)s:%(serverport)s -> %(clientip)s:%(clientport)s (%(serverbytes)s bytes)
</h2>
%(data)s
"""
    _DEFAULT_FORMAT = _PACKET_FORMAT
    _DEFAULT_DELIM = "<br />"

    _HTML_HEADER = """
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Dshell Output</title>
    <style>
        body {
            font-family: monospace;
            font-size: 10pt;
            white-space: pre;
        }
        h1 {
            font-family: helvetica;
            font-size: 13pt;
            font-weight: bolder;
            white-space: pre;
        }
        h2 {
            font-family: helvetica;
            font-size: 12pt;
            font-weight: bolder;
            margin: 0 0;
            white-space: pre;
        }
    </style>
</head>
<body>
"""

    _HTML_FOOTER = """
</body>
</html>
"""

    def __init__(self, *args, **kwargs):
        "Can be called with an optional 'hex' argument to display output in hex"
        super().__init__(*args, **kwargs)
        self.counter = 1
        self.colors = {
            'cs': 'red',   # client-to-server is red
            'sc': 'green',   # server-to-client is green
            '--': 'blue',   # everything else is blue
        }
        self.hexmode = kwargs.get('hex', False)
        self.format_is_set = False

    def setup(self):
        # activate color blind friendly mode
        if self.cbf:
            self.colors['cs'] = 'gold'   # client-to-server is gold (darker yellow)
            self.colors['sc'] = 'seagreen'   # server-to-client is sea green (lighter green)
        self.fh.write(self._HTML_HEADER)

    def write(self, *args, **kwargs):
        if not self.format_is_set:
            if 'clientip' in kwargs:
                self.set_format(self._CONNECTION_FORMAT)
            else:
                self.set_format(self._PACKET_FORMAT)
            self.format_is_set = True

        # a template string for data output
        colorformat = '<span style="color:%s;">%s</span>'

        # Iterate over the args and try to parse out any raw data strings
        rawdata = []
        for arg in args:
            if type(arg) == dshell.core.Blob:
                if arg.data:
                    rawdata.append((arg.data, arg.direction))
            elif type(arg) == dshell.core.Connection:
                for blob in arg.blobs:
                    if blob.data:
                        rawdata.append((blob.data, blob.direction))
            elif type(arg) == dshell.core.Packet:
                rawdata.append((arg.pkt.body_bytes, kwargs.get('direction', '--')))
            elif type(arg) == tuple:
                rawdata.append(arg)
            else:
                rawdata.append((arg, kwargs.get('direction', '--')))

        # Clean up the rawdata into something more presentable
        if self.hexmode:
            cleanup_func = dshell.util.hex_plus_ascii
        else:
            cleanup_func = dshell.util.printable_text
        for k, v in enumerate(rawdata):
            newdata = cleanup_func(v[0])
            newdata = escape(newdata)
            rawdata[k] = (newdata, v[1])

        # Convert the raw data strings into color-coded output
        data = []
        for arg in rawdata:
            datastring = colorformat % (self.colors.get(arg[1], ''), arg[0])
            data.append(datastring)

        super().write(counter=self.counter, *data, **kwargs)
        self.counter += 1

    def close(self):
        self.fh.write(self._HTML_FOOTER)
        Output.close(self)

obj = HTMLOutput


"""
Hypertext Transfer Protocol.
"""
import re
import logging

from pypacker import pypacker, triggerlist

logger = logging.getLogger("pypacker")

# [Method] [Path] HTTP...\r\n
# key: value\r\n
# \r\n
# [body]
PROG_STARTLINE			= re.compile(rb"[\w\./]{3,10} +[\w\./]{1,400} +[\w\./]{1,20}.+")
PROG_STARTLINE_MATCH		= PROG_STARTLINE.match
PROG_SPLIT_HEADBODY		= re.compile(b"\r\n\r\n")
PROG_SPLIT_HEADBODY_SPLIT	= PROG_SPLIT_HEADBODY.split
PROG_SPLIT_HEADER		= re.compile(b"\r\n")
PROG_SPLIT_HEADER_SPLIT		= PROG_SPLIT_HEADER.split
PROG_SPLIT_KEYVAL		= re.compile(b": ")
PROG_SPLIT_KEYVAL_SPLIT		= PROG_SPLIT_KEYVAL.split

PROG_CHUNKSTART_HEADER_d_CRNL	= re.compile(rb"^(\w+)\r\n")

HTTP_PROTO_IPP_REQ	= b"ipp_req"  # Via HTTP request
HTTP_PROTO_IPP_RESP	= b"ipp_resp"  # Via HTTP response


class HTTP(pypacker.Packet):
	class HTTPHeaderTL(triggerlist.TriggerList):
		def _pack(self, tuple_entry):
			# logger.debug("packing HTTP-header")
			# no header = no CRNL
			if len(self) == 0:
				# logger.debug("empty buf 2")
				return b""
			#return b"\r\n".join([b": ".join(keyval) for keyval in self]) + b"\r\n\r\n"
			#logger.debug("adding: %r" % (tuple_entry[0] +b": "+ tuple_entry[1] + b"\r\n"))
			# Note: does not preserve deviating separators, eg "x  :   yz"
			return tuple_entry[0] + b": " + tuple_entry[1] + b"\r\n"

	__hdr__ = (
		# content: b"startline"
		("startline", None, None),  # Including trailing \r\n
		# content: [("name", "value"), ...]
		("hdr", None, HTTPHeaderTL),  # Including trailing \r\n
		("sep", "2s", b"\r\n")
	)

	"""
	TODO: higher layer are more prone to segmentation -> skip higher layer dissecting? Manual dissecting needed?
	__handler__ = {
		HTTP_PROTO_IPP_REQ: ipp.IPPRequest,
		HTTP_PROTO_IPP_RESP: ipp.IPPResponse
	}
	"""

	def _dissect(self, buf):
		# Requestline: [method] [uri] [version] eg GET / HTTP/1.1
		# Responseline: [version] [status] [reason] eg HTTP/1.1 200 OK
		#logger.debug("Full HTTP: %s", buf)
		# Request/responseline is mendatory to parse header
		# TODO: raise exception to trigger dissect error in __init__?
		if len(buf) == 0 or not PROG_STARTLINE_MATCH(buf):
			self.sep = None
			raise Exception()
			#return 0

		try:
			bts_header, bts_body = PROG_SPLIT_HEADBODY_SPLIT(buf, maxsplit=1)
			#logger.debug("Header: %s\nBody: %s", bts_header, bts_body)
		except ValueError:
			#logger.debug("no startline/header present")
			# Deactivate separator
			self.sep = None
			# Assume this is part of a bigger (splittet) HTTP-message: no header/only body
			return 0

		try:
			startline, bts_header = PROG_SPLIT_HEADER_SPLIT(bts_header, maxsplit=1)
		except ValueError:
			# logger.debug("just startline: %r, hdr length=%d" % (bts_header, len(bts_header) + 4))
			# bts_header was something like "HTTP/1.1 123 status" (\r\n\r\n previously removed)
			self.startline = bts_header + b"\r\n"
			return len(bts_header) + 4  # startline + 2 (CR NL) + 0 (header) + 2 (sep: CR NL) + 0 (body)

		self.startline = startline + b"\r\n"
		# bts_header = hdr1\r\nhdr2 -> hdr1\r\nhdr2\r\n
		self.hdr(memoryview(bts_header + b"\r\n"), self._parse_header)
		# Type extraction, TODO: this is not *that* clean
		# WARNING: requests / responses may not contain "Content-Type"
		"""
		body_id = None
		if b"Content-Type: application/ipp" in bts_body:
			body_id = HTTP_PROTO_IPP_REQ if b"POST" startline else HTTP_PROTO_IPP_RESP
		"""
		# HEADER + "\r\n" + BODY -> newline is part of the header
		return len(buf) - len(bts_body)

	@staticmethod
	def _parse_header(buf):
		#logger.debug("Parsing header: %s", buf)
		header = []
		lines = PROG_SPLIT_HEADER_SPLIT(buf)

		for line in lines:
			#logger.debug("Checking line: %s", line)
			if len(line) == 0:
				break
			try:
				key, val = PROG_SPLIT_KEYVAL_SPLIT(line, 1)
				header.append((key, val))
			except:
				# Not a "key: value" line
				logger.warning("Invalid HTTP line: %s", line)
				header.append(line)

		return header

	def update_content_length(self, newlen=None):
		"""
		newlen -- Use this content length for update if not None, otherwise len(body_bytes)
		return -- New content length
		"""
		HDRNAME_CONTENT_LENGTH = b"Content-Length"
		idx__hdr = self.hdr[lambda h: h[0] == HDRNAME_CONTENT_LENGTH]

		if newlen is None:
			newlen = len(self.body_bytes)

		clenheader_updated = (HDRNAME_CONTENT_LENGTH, ("%d" % newlen).encode())
		#logger.debug("New content length header will be: %r" % str(clenheader_updated))

		if len(idx__hdr) != 0:
			self.hdr[idx__hdr[0][0]] = clenheader_updated
		else:
			self.hdr.append(clenheader_updated)

		return newlen

	def get_unchunked(self):
		"""
		Chunked example:
		4\r\n        (bytes to send)
		Wiki\r\n     (data)
		6\r\n        (bytes to send)
		pedia \r\n   (data)
		E\r\n        (bytes to send)
		in \r\n
		\r\n
		chunks.\r\n  (data)
		0\r\n        (final byte - 0)
		\r\n         (end message
		"""
		body_bts = memoryview(self.body_bytes)
		chunk_start = PROG_CHUNKSTART_HEADER_d_CRNL.search(body_bts)
		off = 0
		bts_unchunked = []

		while chunk_start:
			len_hex_str = chunk_start.group()
			len_of_hex_str = len(len_hex_str)
			chunk_len = int(len_hex_str.strip(), 16)

			if chunk_len == 0:
				#logger.debug("Final chunk reached")
				break

			off_end_chunk = off + len_of_hex_str + chunk_len
			#logger.debug(f"len_hex_str={len_hex_str}, len_of_hex_str={len_of_hex_str}, chunk_len={chunk_len}")

			bts_unchunked.append(body_bts[off + len_of_hex_str: off_end_chunk])
			off = off_end_chunk + 2
			#logger.debug(f"Next chunk? {body_bts[ off: off + 10].tobytes()}")
			chunk_start = PROG_CHUNKSTART_HEADER_d_CRNL.search(body_bts[off:])

		return b"".join(bts_unchunked)

	# TODO: implement setter
	# Note: may need reassemblation before unchunking
	chunked = property(get_unchunked)
"""
Presents useful information points for HTTP sessions
"""


class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="httpdump",
            description="Dump useful information about HTTP sessions",
            bpf="tcp and (port 80 or port 8080 or port 8000)",
            author="amm",
            output=ColorOutput(label=__name__),
            optiondict={
                "maxurilen": {
                    "type": int,
                    "default": 30,
                    "metavar": "LENGTH",
                    "help": "Truncate URLs longer than LENGTH (default: 30). Set to 0 for no truncating."},
                "maxpost": {
                    "type": int,
                    "default": 1000,
                    "metavar": "LENGTH",
                    "help": "Truncate POST bodies longer than LENGTH characters (default: 1000). Set to 0 for no truncating."},
                "maxcontent": {
                    "type": int,
                    "default": 0,
                    "metavar": "LENGTH",
                    "help": "Truncate response bodies longer than LENGTH characters (default: no truncating). Set to 0 for no truncating."},
                "showcontent": {
                    "action": "store_true",
                    "help": "Display response body"},
                "showhtml": {
                    "action": "store_true",
                    "help": "Display only HTML results"},
                "urlfilter": {
                    "type": str,
                    "default": None,
                    "metavar": "REGEX",
                    "help": "Filter to URLs matching this regular expression"}
                }
            )

    def premodule(self):
        if self.urlfilter:
            import re
            self.urlfilter = re.compile(self.urlfilter)

    def http_handler(self, conn, request, response):
        host = request.headers.get('host', conn.serverip)
        url = host + request.uri
        pretty_url = url

        # separate URL-encoded data from the location
        if '?' in request.uri:
            uri_location, uri_data = request.uri.split('?', 1)
            pretty_url = host + uri_location
        else:
            uri_location, uri_data = request.uri, ""

        # Check if the URL matches a user-defined filter
        if self.urlfilter and not self.urlfilter.search(pretty_url):
            return

        if self.maxurilen > 0 and len(uri_location) > self.maxurilen:
            uri_location = "{}[truncated]".format(uri_location[:self.maxurilen])
            pretty_url = host + uri_location

        # Set the first line of the alert to show some basic metadata
        if response == None:
            msg = ["{} (NO RESPONSE) {}".format(request.method, pretty_url)]
        else:
            msg = ["{} ({}) {} ({})".format(request.method, response.status, pretty_url, response.headers.get("content-type", "[no content-type]"))]

        # Determine if there is any POST data from the client and parse
        if request and request.method == "POST":
            try:
                post_params = parse_qs(request.body.decode("utf-8"), keep_blank_values=True)
                # If parse_qs only returns a single element with a null
                # value, it's probably an eroneous evaluation. Most likely
                # base64 encoded payload ending in an '=' character.
                if len(post_params) == 1 and list(post_params.values()) == [["\x00"]]:
                    post_params = request.body
            except UnicodeDecodeError:
                post_params = request.body
        else:
            post_params = {}

        # Get some additional useful data
        url_params = parse_qs(uri_data, keep_blank_values=True)
        referer = request.headers.get("referer", None)
        client_cookie = cookies.SimpleCookie(request.headers.get("cookie", ""))
        server_cookie = cookies.SimpleCookie(response.headers.get("cookie", ""))

        # Piece together the alert message
        if referer:
            msg.append("Referer: {}".format(referer))

        if client_cookie:
            msg.append("Client Transmitted Cookies:")
            for k, v in client_cookie.items():
                msg.append("\t{} -> {}".format(k, v.value))

        if server_cookie:
            msg.append("Server Set Cookies:")
            for k, v in server_cookie.items():
                msg.append("\t{} -> {}".format(k, v.value))

        if url_params:
            msg.append("URL Parameters:")
            for k, v in url_params.items():
                msg.append("\t{} -> {}".format(k, v))

        if post_params:
            if isinstance(post_params, dict):
                msg.append("POST Parameters:")
                for k, v in post_params.items():
                    msg.append("\t{} -> {}".format(k, v))
            else:
                msg.append("POST Data:")
                msg.append(dshell.util.printable_text(str(post_params)))
        elif request.body:
            msg.append("POST Body:")
            request_body = dshell.util.printable_text(request.body)
            if self.maxpost > 0 and len(request.body) > self.maxpost:
                msg.append("{}[truncated]".format(request_body[:self.maxpost]))
            else:
                msg.append(request_body)

        if self.showcontent or self.showhtml:
            if self.showhtml and 'html' not in response.headers.get('content-type', ''):
                return
            if 'gzip' in response.headers.get('content-encoding', ''):
                # TODO gunzipping
                content = '(gzip encoded)\n{}'.format(response.body)
            else:
                content = response.body
            content = dshell.util.printable_text(content)
            if self.maxcontent and len(content) > self.maxcontent:
                content = "{}[truncated]".format(content[:self.maxcontent])
            msg.append("Body Content:")
            msg.append(content)

        # Display the start and end times based on Blob instead of Connection
        kwargs = conn.info()
        if request:
            kwargs['starttime'] = request.blob.starttime
            kwargs['clientbytes'] = len(request.blob.data)
        else:
            kwargs['starttime'] = None
            kwargs['clientbytes'] = 0
        if response:
            kwargs['endtime'] = response.blob.endtime
            kwargs['serverbytes'] = len(response.blob.data)
        else:
            kwargs['endtime'] = None
            kwargs['serverbytes'] = 0

        if post_params:
            kwargs['post_params'] = post_params
        if url_params:
            kwargs['url_params'] = url_params
        if client_cookie:
            kwargs['client_cookie'] = client_cookie
        if server_cookie:
            kwargs['server_cookie'] = server_cookie

        self.write('\n'.join(msg), **kwargs)

        return conn, request, response
"""
This is a base-level plugin inteded to handle HTTP connections.

It inherits from the base ConnectionPlugin and provides a new handler
function: http_handler(conn, request, response).

It automatically pairs requests/responses, parses headers, reassembles bodies,
and collects them into HTTPRequest and HTTPResponse objects that are passed
to the http_handler.
"""


logger = logging.getLogger(__name__)


def parse_headers(obj, f):
    """Return dict of HTTP headers parsed from a file object."""
    # Logic lifted mostly from dpkt's http module
    d = {}
    while 1:
        line = f.readline()
        line = line.decode('utf-8')
        line = line.strip()
        if not line:
            break
        l = line.split(None, 1)
        if not l[0].endswith(':'):
            raise dshell.core.DataError("Invalid header {!r}".format(line))
        k = l[0][:-1].lower()
        v = len(l) != 1 and l[1] or ''
        if k in d:
            if not type(d[k]) is list:
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def parse_body(obj, f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict."""
    # Logic lifted mostly from dpkt's http module
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        l = []
        found_end = False
        while 1:
            try:
                sz = f.readline().split(None, 1)[0]
            except IndexError:
                obj.errors.append(dshell.core.DataError('missing chunk size'))
                # FIXME: If this error occurs sz is not available to continue parsing!
                #   The appropriate exception should be thrown.
                raise
            n = int(sz, 16)
            if n == 0:
                found_end = True
            buf = f.read(n)
            if f.readline().strip():
                break
            if n and len(buf) == n:
                l.append(buf)
            else:
                break
        if not found_end:
            raise dshell.core.DataError('premature end of chunked body')
        body = b''.join(l)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            obj.errors.append(dshell.core.DataError('short body (missing {} bytes)'.format(n - len(body))))
    elif 'content-type' in headers:
        body = f.read()
    else:
        # XXX - need to handle HTTP/0.9
        body = b''
    return body


class HTTPRequest(object):
    """
    A class for HTTP requests

    Attributes:
        blob    : the Blob instance of the request
        errors  : a list of caught exceptions from parsing
        method  : the method of the request (e.g. GET, PUT, POST, etc.)
        uri     : the URI being requested (host not included)
        version : the HTTP version (e.g. "1.1" for "HTTP/1.1")
        headers : a dictionary containing the headers and values
        body    : bytestring of the reassembled body, after the headers
    """
    _methods = (
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
        )

    def __init__(self, blob):
        self.errors = []
        self.headers = {}
        self.body = b''
        self.blob = blob
        data = io.BytesIO(blob.data)
        rawline = data.readline()
        try:
            line = rawline.decode('utf-8')
        except UnicodeDecodeError:
            line = ''
        l = line.strip().split()
        if len(l) != 3 or l[0] not in self._methods or not l[2].startswith('HTTP'):
            self.errors.append(dshell.core.DataError('invalid HTTP request: {!r}'.format(rawline)))
            self.method = ''
            self.uri = ''
            self.version = ''
            return
        else:
            self.method = l[0]
            self.uri = l[1]
            self.version = l[2][5:]
        self.headers = parse_headers(self, data)
        self.body = parse_body(self, data, self.headers)


class HTTPResponse(object):
    """
    A class for HTTP responses

    Attributes:
        blob    : the Blob instance of the request
        errors  : a list of caught exceptions from parsing
        version : the HTTP version (e.g. "1.1" for "HTTP/1.1")
        status  : the status code of the response (e.g. "200" or "304")
        reason  : the status text of the response (e.g. "OK" or "Not Modified")
        headers : a dictionary containing the headers and values
        body    : bytestring of the reassembled body, after the headers
    """
    def __init__(self, blob):
        self.errors = []
        self.headers = {}
        self.body = b''
        self.blob = blob
        data = io.BytesIO(blob.data)
        rawline = data.readline()
        try:
            line = rawline.decode('utf-8')
        except UnicodeDecodeError:
            line = ''
        l = line.strip().split(None, 2)
        if len(l) < 2 or not l[0].startswith("HTTP") or not l[1].isdigit():
            self.errors.append(dshell.core.DataError('invalid HTTP response: {!r}'.format(rawline)))
            self.version = ''
            self.status = ''
            self.reason = ''
            return
        else:
            self.version = l[0][5:]
            self.status = l[1]
            self.reason = l[2]
        self.headers = parse_headers(self, data)
        self.body = parse_body(self, data, self.headers)

    def decompress_gzip_content(self):
        """
        If this response has Content-Encoding set to something with "gzip",
        this function will decompress it and store it in the body.
        """
        if "gzip" in self.headers.get("content-encoding", ""):
            try:
                iobody = io.BytesIO(self.body)
            except TypeError as e:
                # TODO: Why would body ever not be bytes? If it's not bytes, then that means
                #   we have a bug somewhere in the code and therefore should just allow the
                #   original exception to be raised.
                self.errors.append(dshell.core.DataError("Body was not a byte string ({!s}). Could not decompress.".format(type(self.body))))
                return
            try:
                self.body = gzip.GzipFile(fileobj=iobody).read()
            except OSError as e:
                self.errors.append(OSError("Could not gunzip body. {!s}".format(e)))
                return


class HTTPPlugin(dshell.core.ConnectionPlugin):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Use "gunzip" argument to automatically decompress gzipped responses
        self.gunzip = kwargs.get("gunzip", False)

    def connection_handler(self, conn):
        """
        Goes through each Blob in a Connection, assuming they appear in pairs
        of requests and responses, and builds HTTPRequest and HTTPResponse
        objects.

        After a response (or only a request at the end of a connection),
        http_handler is called. If it returns nothing, the respective blobs
        are marked as hidden so they won't be passed to additional plugins.
        """
        request = None
        response = None
        for blob in conn.blobs:
            # blob.reassemble(allow_overlap=True, allow_padding=True)
            if not blob.data:
                continue
            if blob.direction == 'cs':
                # client-to-server request
                request = HTTPRequest(blob)
                for req_error in request.errors:
                    self.debug("Request Error: {!r}".format(req_error))
            elif blob.direction == 'sc':
                # server-to-client response
                response = HTTPResponse(blob)
                for rep_error in response.errors:
                    self.debug("Response Error: {!r}".format(rep_error))
                if self.gunzip:
                    response.decompress_gzip_content()
                http_handler_out = self.http_handler(conn=conn, request=request, response=response)
                if not http_handler_out:
                    if request:
                        request.blob.hidden = True
                    if response:
                        response.blob.hidden = True
                request = None
                response = None
        if request and not response:
            http_handler_out = self.http_handler(conn=conn, request=request, response=None)
            if not http_handler_out:
                blob.hidden = True
        return conn

    def http_handler(self, conn, request, response):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites
        on HTTP data.

        It SHOULD return a list containing the sames types of values that came
        in as arguments (i.e. return (conn, request, response)) or None. This
        is mostly a consistency thing. Realistically, it only needs to return
        some value that evaluates to True to pass the Blobs along to additional
        plugins.

        Arguments:
            conn:       a Connection object
            request:    a HTTPRequest object
            response:   a HTTPResponse object
        """
        return conn, request, response

DshellPlugin = None

####################################################################
#
#
#           DSHELL H SCRIPTS END
#
#
###################################################################



####################################################################
#
#
#           DSHELL I SCRIPTS START
#
#
###################################################################


"""
Internet Control Message Protocol for IPv4.
https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
https://tools.ietf.org/html/rfc792
"""

logger = logging.getLogger("pypacker")


# Types (icmp_type) and codes (icmp_code)
# http://www.iana.org/assignments/icmp-parameters
ICMP_ECHO_REPLY			= 0	# echo reply
ICMP_UNREACH			= 3	# dest unreachable
ICMP_SRCQUENCH			= 4	# packet lost, slow down
ICMP_REDIRECT			= 5	# shorter route
ICMP_ALTHOSTADDR		= 6	# alternate host address
ICMP_ECHO			= 8	# echo service
ICMP_RTRADVERT			= 9	# router advertise
ICMP_RTRSEL			= 10	# router selection
ICMP_TIMEXCEED			= 11	# time exceeded, code:
ICMP_PARAMPROB			= 12	# ip header bad
ICMP_TSTAMP			= 13	# timestamp request
ICMP_TSTAMPREPLY		= 14	# timestamp reply
ICMP_INFO			= 15	# information request
ICMP_INFOREPLY			= 16	# information reply
ICMP_MASK			= 17	# address mask request
ICMP_MASKREPLY			= 18	# address mask reply
ICMP_TRACEROUTE			= 30	# traceroute
ICMP_DATACONVERR		= 31	# data conversion error
ICMP_MOBILE_REDIRECT		= 32	# mobile host redirect
ICMP_IP6_WHEREAREYOU		= 33	# IPv6 where-are-you
ICMP_IP6_IAMHERE		= 34	# IPv6 i-am-here
ICMP_MOBILE_REG			= 35	# mobile registration req
ICMP_MOBILE_REGREPLY		= 36	# mobile registration reply
ICMP_DNS			= 37	# domain name request
ICMP_DNSREPLY			= 38	# domain name reply
ICMP_SKIP			= 39	# SKIP
ICMP_PHOTURIS			= 40	# Photuris


CODE_UNREACH_NET = 0  # bad net
CODE_UNREACH_HOST = 1  # bad host
CODE_UNREACH_PROTO = 2  # bad protocol
CODE_UNREACH_PORT = 3  # bad port
CODE_UNREACH_NEEDFRAG = 4  # IP_DF caused drop
CODE_UNREACH_SRCFAIL = 5  # src route failed
CODE_UNREACH_NET_UNKNOWN = 6  # unknown net
CODE_UNREACH_HOST_UNKNOWN = 7  # unknown host
CODE_UNREACH_ISOLATED = 8  # src host isolated
CODE_UNREACH_NET_PROHIB = 9  # for crypto devs
CODE_UNREACH_HOST_PROHIB = 10  # ditto
CODE_UNREACH_TOSNET = 11  # bad tos for net
CODE_UNREACH_TOSHOST = 12  # bad tos for host
CODE_UNREACH_FILTER_PROHIB = 13  # prohibited access
CODE_UNREACH_HOST_PRECEDENCE = 14  # precedence error
CODE_UNREACH_PRECEDENCE_CUTOFF = 15  # precedence cutoff

CODE_REDIRECT_NET = 0  # for network
CODE_REDIRECT_HOST = 1  # for host
CODE_REDIRECT_TOSNET = 2  # for tos and net
CODE_REDIRECT_TOSHOST = 3  # for tos and host

CODE_PHOTURIS_UNKNOWN_INDEX = 0  # unknown sec index
CODE_PHOTURIS_AUTH_FAILED = 1  # auth failed
CODE_PHOTURIS_DECOMPRESS_FAILED = 2  # decompress failed
CODE_PHOTURIS_DECRYPT_FAILED = 3  # decrypt failed
CODE_PHOTURIS_NEED_AUTHN = 4  # no authentication
CODE_PHOTURIS_NEED_AUTHZ = 5  # no authorization

CODE_RTRADVERT_NORMAL = 0  # normal
CODE_RTRADVERT_NOROUTE_COMMON = 16  # selective routing
CODE_RTRSOLICIT = 10  # router solicitation

CODE_TIMEXCEED_INTRANS = 0  # ttl==0 in transit
CODE_TIMEXCEED_REASS = 1  # ttl==0 in reass

CODE_PARAMPROB_ERRATPTR = 0  # req. opt. absent
CODE_PARAMPROB_OPTABSENT = 1  # req. opt. absent
CODE_PARAMPROB_LENGTH = 2  # bad length


class ICMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", ICMP_ECHO, FIELD_FLAG_IS_TYPEFIELD),
		("code", "B", 0), # Code depends on type
		# Place sum here and not higher layer: otherwise..
		# - higher layer needs to access lower layer for sum
		# - duplicated code
		# Additionally code has to be placed here, too
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)

	def _update_fields(self):
		# logger.debug("sum is: %d" % self.sum)
		if self.sum_au_active and self._changed():
			# logger.debug("sum is: %d" % self.sum)
			# logger.debug("header: %r", self.header_bytes)
			# logger.debug("body: %r", self.body_bytes)
			self.sum = 0
			self.sum = checksum.in_cksum(self.header_bytes + self.body_bytes)
			# logger.debug("sum is: %d" % self.sum)

	def _dissect(self, buf):
		# logger.debug("ICMP: adding fields for type: %d" % buf[0])
		return 4, buf[0]

	class Echo(pypacker.Packet):
		__hdr__ = (
			("id", "H", 0),
			("seq", "H", 1)
		)

	class Unreach(pypacker.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

	class Quench(pypacker.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

	class Redirect(pypacker.Packet):
		__hdr__ = (
			("gw", "I", 0),
		)

	class RouterAdvertisement(pypacker.Packet):
		__hdr__ = (
			("numaddr", "B", 0),
			("addrsize", "B", 0),
			("lifetime", "H", 0)
		)

	class RouterSelection(pypacker.Packet):
		__hdr__ = (
			("numaddr", "B", 0),
			("addrsize", "B", 0),
			("lifetime", "H", 0)
		)

	class TimeExceed(pypacker.Packet):
		__hdr__ = (
			("pad", "I", 0),
		)

	class ParamProblem(pypacker.Packet):
		__hdr__ = (
			("pointer", "B", 0),
			("unused", "3s", b"\x00" * 3)
		)

	class Photuris(pypacker.Packet):
		class ParamProblem(pypacker.Packet):
			__hdr__ = (
				("reserved", "H", 0),
				("pointer", "H", 0)
			)

	@staticmethod
	def _trl_code_create_descr_cb():
		type__code__name = pypacker.recusive_dict()
		variables_name__value = globals()

		for vname, vvalue in variables_name__value.items():
			type_key = None

			if "UNREACH" in vname:
				type_key = ICMP_UNREACH
			elif "REDIRECT" in vname:
				type_key = ICMP_REDIRECT
			elif "PHOTURIS" in vname:
				type_key = ICMP_PHOTURIS
			elif "RTRADVERT" in vname:
				type_key = ICMP_RTRADVERT
			elif "TIMEXCEED" in vname:
				type_key = ICMP_TIMEXCEED
			elif "PARAMPROB" in vname:
				type_key = ICMP_PARAMPROB

			if type_key is not None:
				pkg_mod = ICMP.__module__.split(".") # pypacker, layerX, icmp
				type__code__name[type_key][vvalue] = pkg_mod[2] + "." + vname, \
					(pkg_mod[0] + "." + pkg_mod[1], pkg_mod[2], "", vname)

		return type__code__name

	@staticmethod
	def _trl_code_get_description_cb(obj_self, code, type__code__name):
		if obj_self.type not in type__code__name:
			return "", []
		return type__code__name[obj_self.type].get(code, ("", []))

	# TODO: add test cases
	# - Correct description on 1-dim trl
	# - Correct description on 2-dim trl
	type_t = pypacker.get_property_translator("type", "ICMP_")
	code_t = pypacker.get_property_translator("code", "CODE_",
			cb_create_descriptions=_trl_code_create_descr_cb,
			cb_get_description=_trl_code_get_description_cb
		) # noqa E124

	__handler__ = {
		(ICMP_ECHO, ICMP_ECHO_REPLY): Echo,
		ICMP_UNREACH: Unreach,
		ICMP_SRCQUENCH: Quench,
		ICMP_REDIRECT: Redirect,
		ICMP_RTRADVERT: RouterAdvertisement,
		ICMP_RTRSEL: RouterSelection,
		ICMP_TIMEXCEED: TimeExceed,
		ICMP_PARAMPROB: ParamProblem,
		ICMP_PHOTURIS: Photuris
	}

"""
Internet Control Message Protocol for IPv6.
https://tools.ietf.org/html/rfc2463
"""

logger = logging.getLogger("pypacker")


# See https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-codes-2
ICMP6_DST_UNREACH		= 1		# dest unreachable, codes:
ICMP6_PACKET_TOO_BIG		= 2		# packet too big
ICMP6_TIME_EXCEEDED		= 3		# time exceeded, code:
ICMP6_PARAM_PROB		= 4		# ip6 header bad
ICMP6_ECHO_REQUEST		= 128		# echo service
ICMP6_ECHO_REPLY		= 129		# echo reply
ICMP6_MCAST_LISTENER_QUERY	= 130		# multicast listener query
ICMP6_MCAST_LISTENER_REPORT	= 131		# multicast listener report
ICMP6_MCAST_LISTENER_DONE	= 132		# multicast listener done
ICMP6_ROUTER_SOLICIT		= 133		# router solicitation
ICMP6_ROUTER_ADVERT		= 134		# router advertisment
ICMP6_NEIGHBOR_SOLICIT		= 135		# neighbor solicitation
ICMP6_NEIGHBOR_ADVERT		= 136		# neighbor advertisment
ICMP6_REDIRECT			= 137		# redirect
ICMP6_ROUTER_RENUMBERING	= 138		# router renumbering
ICMP6_NODE_INFO_QUERY		= 139		# who are you request
ICMP6_NODE_INFO_REPLY		= 140		# who are you reply


CODE_UNREACH_NOROUTE_DO_DST		= 0
CODE_UNREACH_COMM_DST_PROHIB		= 1
CODE_UNREACH_BEYOND_SCOPE_SRC		= 2
CODE_UNREACH_ADDR_UNREACH		= 3
CODE_UNREACH_PORT_UNREACH		= 4
CODE_UNREACH_SRC_ADDR_FAILED_POLICY	= 5
CODE_UNREACH_REJECT_ROUTE_TO_DST	= 6
CODE_UNREACH_ERROR_IN_SRC_ROUTING	= 7
CODE_UNREACH_HEADERS_TOO_LONG		= 8

CODE_PARAM_PROB_ERR_HEADER				= 0
CODE_PARAM_PROB_UNRECOGNIZED_NXT_HEADER_TYPE		= 1
CODE_PARAM_PROB_UNRECOGNIZED_IPV6_OPTION		= 2
CODE_PARAM_PROB_IPV6_INCOMPLETE_HEADER_CHAIN		= 3
CODE_PARAM_PROB_SR_UPPER_LAYER_ERR			= 4
CODE_PARAM_PROB_UNRECOGNIZED_NXT_HEADER_TYPE_BY_IM_NODE = 5
CODE_PARAM_PROB_EXT_HEADER_TOO_BIG			= 6
CODE_PARAM_PROB_EXT_HEADER_CHAIN_TOO_LONG		= 7
CODE_PARAM_PROB_TOO_MANY_EXT_HEADERS			= 8
CODE_PARAM_PROB_TOO_MANY_OPTIONS_IN_EXT_HEADER		= 9
CODE_PARAM_PROB_OPT_TOO_BIG				= 10

CODE_TIMEEXCEED_HOP_LIMIT_EXCEED	= 0
CODE_TIMEEXCEED_FRAG_REASSEMBLY		= 1


#
# Option codes
#
OPT_TYPE_SRC_LL = 1
OPT_TYPE_PREFIX_INFO = 3
OPT_TYPE_MTU = 5
OPT_ROUTEINFO = 24
OPT_TYPE_RECUSRICE_DNS = 25


pack_ipv6_icmp6 = struct.Struct(">16s16sII").pack
checksum_in_cksum = checksum.in_cksum


class ICMP6(pypacker.Packet):
	__hdr__ = (
		("type", "B", ICMP6_ECHO_REQUEST, FIELD_FLAG_IS_TYPEFIELD),
		# Place sum here and not higher layer: otherwise..
		# - higher layer needs to access lower layer for sum
		# - duplicated code
		# Additionally code has to be placed here, too
		("code", "B", 0), # Code depends on type
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)

	def _dissect(self, buf):
		return 4, buf[0]

	def _calc_sum(self):
		try:
			# We need src/dst for checksum-calculation
			src, dst = self._lower_layer.src, self._lower_layer.dst
		except Exception:
			# Not an IP packet as lower layer (src, dst not present) or invalid src/dst
			# logger.debug("could not calculate checksum: %r" % e)
			return

		# Pseudoheader
		# Packet length = length of upper layers
		self.sum = 0
		# logger.debug("TCP sum recalc: IP6= len(src)=%d\n%s\n%s\nhdr=%s\nbody=%s" %
		#			 (len(src), src, dst, self.header_bytes, self.body_bytes))
		pkt = self.header_bytes + self.body_bytes
		hdr = pack_ipv6_icmp6(src, dst, len(pkt), 58)
		# This will set the header status to changes, should be reset by calling bin()
		self.sum = checksum_in_cksum(hdr + pkt)
		#logger.debug(">>> new checksum: %0X" % self.sum)

	def _update_fields(self):
		try:
			if self.lower_layer._changed():
				self._calc_sum()
		except Exception:
			# no lower layer, nothing to update
			# logger.debug("%r" % ex)
			pass

	class Unreach(pypacker.Packet):
		__hdr__ = (("pad", "I", 0), )

	class TooBig(pypacker.Packet):
		__hdr__ = (
			("pad", "I", 0),
			("mtu", "I", 1232)
		)

	class TimeExceed(pypacker.Packet):
		__hdr__ = (("pad", "I", 0), )

	class ParamProb(pypacker.Packet):
		__hdr__ = (
			("pad", "I", 0),
			("ptr", "I", 0),
		)

	class Echo(pypacker.Packet):
		__hdr__ = (
			("id", "H", 0),
			("seq", "H", 0)
		)

	class NeighbourSolicitation(pypacker.Packet):
		__hdr__ = (
			("rsv", "4s", b"\x00" * 4),
			("target", "16s", b"\x00" * 16),
			("opts", None, triggerlist.TriggerList)
		)

		def _dissect(self, buf):
			self.opts(buf[20:], ICMP6._parse_icmp6opt)
			return len(buf)

		target_s = pypacker.get_property_ip6("target")

	class NeighbourAdvertisement(pypacker.Packet):
		__hdr__ = (
			("flags", "4s", b"\x00" * 4),
			("target", "16s", b"\x00" * 16),
			("opts", None, triggerlist.TriggerList)
		)

		def _dissect(self, buf):
			self.opts(buf[20:], ICMP6._parse_icmp6opt)
			return len(buf)

		target_s = pypacker.get_property_ip6("target")

	class RouterSolicitation(pypacker.Packet):
		__hdr__ = (
			("reserved", "I", 0),
		)

	class MulticastRouterSolicitation(pypacker.Packet):
		__hdr__ = (
			("reserved", "I", 0),
		)

	class RouterAdvertisement(pypacker.Packet):
		__hdr__ = (
			("hop", "B", 0),
			("flags", "B", 0),
			("rlife", "H", 0),
			("reachable_time", "I", 0),
			("retrans_time", "I", 0),
			# eg Source link/1, MTU/5, Prefix Info/3
			("opts", None, triggerlist.TriggerList)
		)

		class SourceLLOpt(pypacker.Packet):
			__hdr__ = (
				("type", "B", OPT_TYPE_SRC_LL),
				("len", "B", 1),
				("addr", None, b"\x00" * 6)
			)

			addr_s = pypacker.get_property_mac("addr")

		class PrefixOpt(pypacker.Packet):
			__hdr__ = (
				("type", "B", OPT_TYPE_PREFIX_INFO),
				("len", "B", 4),
				("plen", "B", 64),
				("flags", "B", 0xC0),
				("lifetime", "I", 2592000),
				("preftime", "I", 604800),
				("reserved", "I", 0),
				("prefix", None, b"\x00" * 16)
			)

			# TODO: Format depends on type
			prefix_s = pypacker.get_property_ip6("prefix")

		class RouteOpt(pypacker.Packet):
			__hdr__ = (
				("type", "B", OPT_ROUTEINFO),
				("len", "B", 3),
				("plen", "B", 128),
				("flags", "B", 0x08),
				("routelt", "I", 4096),
				("prefix", None, b"\x00" * 16)
			)

			prefix_s = pypacker.get_property_ip6("prefix")

		class MTUOpt(pypacker.Packet):
			__hdr__ = (
				("type", "B", OPT_TYPE_MTU),
				("len", "B", 1),
				("reserved", "H", 0),
				("mtu", "I", 0)
			)

		class RecursiveDNSOpt(pypacker.Packet):
			__hdr__ = (
				("type", "B", OPT_TYPE_RECUSRICE_DNS),
				("len", "B", 3),
				("reserved", "H", 0),
				("ltime", "I", 0),
				("dnsserver", "16s", b"\x00" * 16)
			)

			addr_s = pypacker.get_property_ip6("dnsserver")

		def _dissect(self, buf):
			self.opts(buf[12:], ICMP6._parse_icmp6opt)
			return len(buf)

	class MulticastRouterAdvertisement(pypacker.Packet):
		__hdr__ = (
			("qinterval", "H", 0x30),
			("robustness", "H", 0x06),
		)

	class MulticastListenerQuery(pypacker.Packet):
		__hdr__ = (
			("maxdelay", "H", 0),
			("reserved", "H", 0),
			("addr", "16s", b"\x00" * 16)
		)

		class MLDv2(pypacker.Packet):
			__hdr__ = (
				("flags", "B", 0x07),
				("QQIC", "B", 0x78),
				("sources", "H", 0)
			)

	class MulticastListenerReport(pypacker.Packet):
		__hdr__ = (
			("reserved", "H", 0),
			("addrcnt", "H", 0),
			("records", None, triggerlist.TriggerList),
		)

		class Record(pypacker.Packet):
			TYPE_INCLUDE = 3

			__hdr__ = (
				("type", "B", 3),
				("len", "B", 0),
				("sources", "H", 0),
				("addr", "16s", b"\x00" * 16)
			)

	@staticmethod
	def _parse_icmp6opt(buf):
		opts = []
		off = 0

		while off < len(buf):
			optlen = buf[off + 1] * 8
			opt = ICMP6.ICMPv6Opt(buf[off: off + optlen])
			opts.append(opt)
			off += optlen
		return opts

	@staticmethod
	def _trl_code_create_descr_cb():
		type__code__name = pypacker.recusive_dict()
		variables_name__value = globals()

		for vname, vvalue in variables_name__value.items():
			type_key = None

			if "UNREACH" in vname:
				type_key = ICMP6_DST_UNREACH
			elif "TIMEXCEED" in vname:
				type_key = ICMP6_TIME_EXCEEDED
			elif "PARAM_PROB" in vname:
				type_key = ICMP6_PARAM_PROB

			if type_key is not None:
				pkg_mod = ICMP6.__module__.split(".") # pypacker, layerX, icmp6
				type__code__name[type_key][vvalue] = pkg_mod[2] + "." + vname, \
					(pkg_mod[0] + "." + pkg_mod[1], pkg_mod[2], "", vname)

		return type__code__name

	@staticmethod
	def _trl_code_get_description_cb(obj_self, code, type__code__name):
		if obj_self.type not in type__code__name:
			return "", []
		return type__code__name[obj_self.type].get(code, ("", []))

	type_t = pypacker.get_property_translator("type", "ICMP6_")
	code_t = pypacker.get_property_translator("code", "CODE_",
			cb_create_descriptions=_trl_code_create_descr_cb,
			cb_get_description=_trl_code_get_description_cb
		) # noqa E124

	__handler__ = {
		ICMP6_DST_UNREACH: Unreach,
		ICMP6_PACKET_TOO_BIG: TooBig,
		ICMP6_TIME_EXCEEDED: TimeExceed,
		ICMP6_PARAM_PROB: ParamProb,
		ICMP6_ECHO_REQUEST: Echo,
		ICMP6_ECHO_REPLY: Echo,
		ICMP6_NEIGHBOR_SOLICIT: NeighbourSolicitation,
		ICMP6_NEIGHBOR_ADVERT: NeighbourAdvertisement,
		ICMP6_ROUTER_ADVERT: RouterAdvertisement
	}

"""IEEE 802.11"""

logger = logging.getLogger("pypacker")


# Frame Types
MGMT_TYPE		= 0
CTL_TYPE		= 1
DATA_TYPE		= 2

# Frame Sub-Types
# MGMT_TYPE
M_ASSOC_REQ		= 0
M_ASSOC_RESP		= 1
M_REASSOC_REQ		= 2
M_REASSOC_RESP		= 3
M_PROBE_REQ		= 4
M_PROBE_RESP		= 5
M_DISASSOC		= 10
M_AUTH			= 11
M_DEAUTH		= 12
M_ACTION		= 13
M_BEACON		= 8
M_ATIM			= 9

# CTL_TYPE
C_BLOCK_ACK_REQ		= 8
C_BLOCK_ACK		= 9
C_PS_POLL		= 10
C_RTS			= 11
C_CTS			= 12
C_ACK			= 13
C_CF_END		= 14
C_CF_END_ACK		= 15

# DATA_TYPE
D_NORMAL		= 0
D_DATA_CF_ACK		= 1
D_DATA_CF_POLL		= 2
D_DATA_CF_ACK_POLL	= 3
D_NULL			= 4
D_CF_ACK		= 5
D_CF_POLL		= 6
D_CF_ACK_POLL		= 7
D_QOS_DATA		= 8
D_QOS_CF_ACK		= 9
D_QOS_CF_POLL		= 10
D_QOS_CF_ACK_POLL	= 11
D_QOS_NULL		= 12
D_QOS_CF_POLL_EMPTY	= 14

TO_DS_FLAG		= 1
FROM_DS_FLAG		= 2
INTER_DS_FLAG		= 3


# name : (mask, offset)
_FRAMECTRL_SUBHEADERDATA = {
	"version": (0x0300, 8),
	"type": (0x0C00, 10),
	"subtype": (0xF000, 12),
	"to_ds": (0x0001, 0),
	"from_ds": (0x0002, 1),
	"more_frag": (0x0004, 2),
	"retry": (0x0008, 3),
	"pwr_mgt": (0x0010, 4),
	"more_data": (0x0020, 5),
	"protected": (0x0040, 6),
	"order": (0x0080, 7),
	"from_to_ds": (0x0002 | 0x0001, 0),
}

# needed to distinguish subtypes via types
TYPE_FACTORS		= [16, 32, 64]
TYPE_FACTOR_PROTECTED	= 128

_subheader_properties = []

IEEE_FIELDS_SRC_DST_BSSID = ["src", "dst", "bssid"]

# Set properties to access flags
for subfield_name, mask_off in _FRAMECTRL_SUBHEADERDATA.items():
	# logger.debug("setting prop: %r, %X, %X" % (subfield_name, mask_off[0], mask_off[1]))
	subheader = [
		subfield_name,
		# lambda**2: avoid lexical closure, do not refer to value via reference
		# Could be called in _dissect: used shadowed variable instead
		( # pylint: disable=unnecessary-direct-lambda-call
			lambda mask, off:
			(lambda _obj: ((_obj.framectl if _obj._unpacked is not None else _obj._framectl) & mask) >> off)
		)(mask_off[0], mask_off[1]),
		( # pylint: disable=unnecessary-direct-lambda-call
			lambda mask, off:
			(lambda _obj, _val: setattr(_obj, "framectl", # pylint: disable=unnecessary-direct-lambda-call
				((_obj.framectl if _obj._unpacked is not None else _obj._framectl) & ~mask) | (_val << off)))
		)
		(mask_off[0], mask_off[1]),
	]
	_subheader_properties.append(subheader)


class IEEE80211(pypacker.Packet):
	__hdr__ = (
		# AAAABBCC | 00000000
		# AAAA = subtype BB = type CC = version
		("framectl", "H", 0),
		("duration", "H", 0x3A01)  # 314 microseconds
	)

	__hdr_sub__ = _subheader_properties

	def _dissect(self, buf):
		self._framectl = unpack_H(buf[:2])[0]
		#logger.debug("ieee80211 type/subtype is=%X/%X, handler=%r" %
		#	(self.type, self.subtype,
		#	pypacker.Packet._id_handlerclass_dct[self.__class__][TYPE_FACTORS[self.type] + self.subtype]))
		return 4, TYPE_FACTORS[self.type] + self.subtype

	def is_beacon(self):
		"""return -- True if packet is a beacon. Avoids parsing upper layer."""
		return self.type == MGMT_TYPE and self.subtype == M_BEACON

	def extract_client_macs(self):
		"""
		Extracts client MACs from upper layer if this is a data packet.

		return -- [mac_client1, ...] or [] if no client macs could be found
		"""
		macs_clients = []

		# data: client -> AP or client <- AP
		if self.type == DATA_TYPE:
			if self.from_ds == 1 and self.to_ds == 0:
				macs_clients.append(self.higher_layer.dst)
			elif self.from_ds == 0 and self.to_ds == 1:
				macs_clients.append(self.higher_layer.src)

		return [addr for addr in macs_clients if not utils.is_special_mac(addr)]

	#
	# mgmt frames
	#
	class Beacon(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			# 12 Bits: 0->4095 | 4 Bits
			# SF SS (LE)
			("seq_frag", "H", 0),
			# _ts (integer) is saved as LE
			("_ts", "Q", 0),
			("interval", "H", 0x6400),
			("capa", "H", 0x0100),
			("params", None, triggerlist.TriggerList)
		)

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		def _get_ts(self):
			# LE->BE: dirty but simple
			return unpack_Q_le(pack_Q(self._ts))[0]

		def _set_ts(self, val):
			self._ts = unpack_Q_le(pack_Q(val))[0]

		def _get_essid(self):
			return self.params[lambda v: v.id == IEEE80211.IE_SSID][0][1].body_bytes

		seq = property(_get_seq, _set_seq)
		ts = property(_get_ts, _set_ts)
		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")
		essid = property(_get_essid)

		def _dissect(self, buf):
			#logger.debug(self.__class__)
			self.params(buf[32:], IEEE80211._unpack_ies)
			return len(buf)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Action(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("category", "B", 0),
			("code", "B", 0)
		)

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		class BlockAckRequest(pypacker.Packet):
			__hdr__ = (
				("dialog", "B", 0),
				("parameters", "H", 0),
				("timeout", "H", 0),
				("starting_seq", "H", 0),
			)

		class BlockAckResponse(pypacker.Packet):
			__hdr__ = (
				("dialog", "B", 0),
				("status_code", "H", 0),
				("parameters", "H", 0),
				("timeout", "H", 0),
			)

		CATEGORY_BLOCK_ACK	= 3
		CODE_BLOCK_ACK_REQUEST	= 0
		CODE_BLOCK_ACK_RESPONSE	= 1

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")
		bssid_s = pypacker.get_property_mac("bssid")

		def _dissect(self, buf):
			# logger.debug(">>>>>>>> ACTION!!!")
			# category: block ack, code: request or response
			return 22, buf[20] * 4 + buf[21]

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ProbeReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self.params(buf[20:], IEEE80211._unpack_ies)
			return len(buf)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ProbeResp(Beacon):
		pass

	class AssocReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("interval", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self.params(buf[24:], IEEE80211._unpack_ies)
			return len(buf)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class AssocResp(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("status", "H", 0),
			("aid", "H", 0),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def _dissect(self, buf):
			self.params(buf[26:], IEEE80211._unpack_ies)
			return len(buf)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Disassoc(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("reason", "H", 0),
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class ReassocReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("capa", "H", 0),
			("interval", "H", 0),
			("current_ap", "6s", b"\x00" * 6),
			("params", None, triggerlist.TriggerList)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

		def _dissect(self, buf):
			self.params(buf[30:], IEEE80211._unpack_ies)
			return len(buf)

	class Auth(pypacker.Packet):
		"""Authentication request."""
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("algo", "H", 0),
			("authseq", "H", 0x0100),
			("status", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class Deauth(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\xff" * 6),
			("src", "6s", b"\x00" * 6),
			("bssid", "6s", b"\xff" * 6),
			("seq_frag", "H", 0),
			("reason", "H", 0x0700)  # class 3 frame received from non associated client
		)

		dst_s = pypacker.get_property_mac("dst")
		bssid_s = pypacker.get_property_mac("bssid")
		src_s = pypacker.get_property_mac("src")

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	m_decoder = {
		M_BEACON: Beacon,
		M_ACTION: Action,
		M_ASSOC_REQ: AssocReq,
		M_ASSOC_RESP: AssocResp,
		M_DISASSOC: Disassoc,
		M_REASSOC_REQ: ReassocReq,
		M_REASSOC_RESP: AssocResp,
		M_AUTH: Auth,
		M_PROBE_REQ: ProbeReq,
		M_PROBE_RESP: ProbeResp,
		M_DEAUTH: Deauth
	}

	#
	# Control frames: no need for extra layer: 802.11 Base data is enough
	#

	class RTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class CTS(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")

	class ACK(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")

	class BlockAckReq(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("reqctrl", "H", 0),
			("seq", "H", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class BlockAck(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
			("reqctrl", "H", 0),
			("seq", "H", 0),
			("bitmap", "Q", 0)
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	class CFEnd(pypacker.Packet):
		__hdr__ = (
			("dst", "6s", b"\x00" * 6),
			("src", "6s", b"\x00" * 6),
		)

		dst_s = pypacker.get_property_mac("dst")
		src_s = pypacker.get_property_mac("src")

		def reverse_address(self):
			self.dst, self.src = self.src, self.dst

	c_decoder = {
		C_RTS: RTS,
		C_CTS: CTS,
		C_ACK: ACK,
		C_BLOCK_ACK_REQ: BlockAckReq,
		C_BLOCK_ACK: BlockAck,
		C_CF_END: CFEnd
	}

	#
	# Data frames
	#
	class Dataframe(pypacker.Packet):
		__hdr__ = (
			("addr1", "6s", b"\x00" * 6),
			("addr2", "6s", b"\x00" * 6),
			("addr3", "6s", b"\x00" * 6),
			("seq_frag", "H", 0),
			("addr4", "6s", None),		# to/from-DS = 1
			("qos_ctrl", "H", 0),		# QoS
			("sec_param", "Q", 0)		# protected
		)

		def _get_seq(self):
			return (self.seq_frag & 0xFF) << 4 | (self.seq_frag >> 12)

		def _set_seq(self, val):
			self.seq_frag = (val & 0xF) << 12 | (val & 0xFF0) >> 4 | (self.seq_frag & 0x0F00)

		seq = property(_get_seq, _set_seq)

		def reverse_address(self):
			if self.from_to_ds == 0:
				self.addr1, self.addr2 = self.addr2, self.addr1
			elif self.from_to_ds == 1:
				self.addr2, self.addr3 = self.addr3, self.addr2
			elif self.from_to_ds == 2:
				self.addr1, self.addr3 = self.addr3, self.addr1

		def _get_from_to_ds(self):
			try:
				return self._lower_layer.from_to_ds
			except:
				return self._from_to_ds

		_from_to_ds = 0

		def _set_from_to_ds(self, value):
			try:
				self._lower_layer.from_to_ds = value
			except:
				self._from_to_ds = value

		# Same property structure as in IEEE80211 class
		from_to_ds = property(_get_from_to_ds, _set_from_to_ds)

		def __get_src(self):
			return self.addr2 if self.from_to_ds in [0, 1] else self.addr3

		def __set_src(self, src):
			if self.from_to_ds in [0, 1]:
				self.addr2 = src
			else:
				self.addr3 = src

		def __get_dst(self):
			return self.addr1 if self.from_to_ds in [0, 2] else self.addr3

		def __set_dst(self, dst):
			if self.from_to_ds in [0, 2]:
				self.addr1 = dst
			else:
				self.addr3 = dst

		def __get_bssid(self):
			dstype = self.from_to_ds

			if dstype == 0:
				return self.addr3
			if dstype == 1:
				return self.addr1
			if dstype == 2:
				return self.addr2

			return None

		def __set_bssid(self, bssid):
			dstype = self.from_to_ds

			if dstype == 0:
				self.addr3 = bssid
			elif dstype == 1:
				self.addr1 = bssid
			elif dstype == 2:
				self.addr2 = bssid

		src = property(__get_src, __set_src)
		src_s = pypacker.get_property_mac("src")
		dst = property(__get_dst, __set_dst)
		dst_s = pypacker.get_property_mac("dst")
		bssid = property(__get_bssid, __set_bssid)
		bssid_s = pypacker.get_property_mac("bssid")

		__QOS_SUBTYPES = {8, 9, 10, 11, 12, 14, 15}

		def _dissect(self, buf):
			# logger.debug("starting dissecting, buflen: %r" % str(buf))
			header_len = 30

			"""
			DataFrames need special care: there are too many types of field combinations
			to create classes for every one. Solution: initiate by taking from_to_ds of lower_layer
			In order to use "src/dst/bssid" instead of addrX set from_to_ds
			to one of the following values:

			[Bit 0: from DS][Bit 1: to DS] = [order of fields]

			00b = 0 = dst, src, bssid
			01b = 1 = bssid, src, dst
			10b = 2 = dst, bssid, src
			11b = 3 = RA, TA, DA, SA
			"""
			if self._lower_layer.__class__ == IEEE80211:
				is_qos = self._lower_layer.subtype in IEEE80211.Dataframe.__QOS_SUBTYPES
				is_protected = self._lower_layer.protected == 1
				is_bridge = self._lower_layer.from_ds == 1 and self._lower_layer.to_ds == 1
			else:
				# Default is fromds
				is_qos = False
				is_protected = False
				is_bridge = False

			# logger.debug("switching fields1")
			if not is_qos:
				self.qos_ctrl = None
				header_len -= 2
			# logger.debug("switching fields2")
			if not is_protected:
				self.sec_param = None
				header_len -= 8
			# logger.debug("switching fields3")
			if is_bridge:
				self.addr4 = b"\x00" * 6
				header_len += 6
			# logger.debug("format/length/len(bin): %s/%d/%d" % (self._hdr_fmtstr, self.hdr_len, len(self.bin())))
			# logger.debug("%r" % self)
			return header_len

	d_decoder = {
		D_NORMAL: Dataframe,
		D_DATA_CF_ACK: Dataframe,
		D_DATA_CF_POLL: Dataframe,
		D_DATA_CF_ACK_POLL: Dataframe,
		D_NULL: Dataframe,
		D_CF_ACK: Dataframe,
		D_CF_POLL: Dataframe,
		D_CF_ACK_POLL: Dataframe,
		D_QOS_DATA: Dataframe,
		D_QOS_CF_ACK: Dataframe,
		D_QOS_CF_POLL: Dataframe,
		D_QOS_CF_ACK_POLL: Dataframe,
		D_QOS_NULL: Dataframe,
		D_QOS_CF_POLL_EMPTY: Dataframe
	}

	#
	# IEs for Mgmt-Frames
	#
	@staticmethod
	def _unpack_ies(buf):
		"""Parse IEs and return them as Triggerlist."""
		# each IE starts with an ID and a length
		ies = []
		off = 0
		buflen = len(buf)

		while off + 2 < buflen:
			ie_id = buf[off]
			try:
				parser = IEEE80211.ie_decoder[ie_id]
			except KeyError:
				# some unknown tag, use standard format
				parser = IEEE80211.IE

			dlen = buf[off + 1]
			#logger.debug("IE parser is: %d = %s = %s" % (ie_id, parser, buf[off: off+2+dlen]))
			try:
				ie = parser(buf[off: off + 2 + dlen])
				ies.append(ie)
			except:
				# Not enough bytes for handler, add raw bytes
				ies.append(buf[off: off + 2 + dlen])
			off += 2 + dlen

		return ies

	class IE(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0)
		)

	class FH(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("tu", "H", 0),
			("hopset", "B", 0),
			("hoppattern", "B", 0),
			("hopindex", "B", 0)
		)

	class DS(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("ch", "B", 0)
		)

	class CF(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("count", "B", 0),
			("period", "B", 0),
			("max", "H", 0),
			("dur", "H", 0)
		)

	class TIM(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("count", "B", 0),
			("period", "B", 0),
			("ctrl", "H", 0)
		)

	class IBSS(pypacker.Packet):
		__hdr__ = (
			("id", "B", 0),
			("len", "B", 0),
			("atim", "H", 0)
		)

	# IEs
	IE_SSID			= 0
	IE_RATES		= 1
	IE_FH			= 2
	IE_DS			= 3
	IE_CF			= 4
	IE_TIM			= 5
	IE_IBSS			= 6
	IE_HT_CAPA		= 45
	IE_ESR			= 50
	IE_HT_INFO		= 61

	ie_decoder = {
		IE_SSID: IE,
		IE_RATES: IE,
		IE_FH: FH,
		IE_DS: DS,
		IE_CF: CF,
		IE_TIM: TIM,
		IE_IBSS: IBSS,
		IE_HT_CAPA: IE,
		IE_ESR: IE,
		IE_HT_INFO: IE
	}


# Handler for IEEE80211
# position in list = type-ID
dicts			= [IEEE80211.m_decoder, IEEE80211.c_decoder, IEEE80211.d_decoder]
decoder_dict_complete	= {}

for pos, decoder_dict in enumerate(dicts):
	for key_decoder, val_decoder in decoder_dict.items():
		# Same subtype-ID for different type-IDs, distinguish via "type_factor + subtype"
		# Not doing so would lead to eg: type:0 + subtype:1 == type:1 + subtype:0
		decoder_dict_complete[TYPE_FACTORS[pos] + key_decoder] = val_decoder

pypacker.Packet.load_handler(IEEE80211, decoder_dict_complete)

# Handler for Action
CATEGORY_BLOCK_ACK_FACTOR = IEEE80211.Action.CATEGORY_BLOCK_ACK * 4
pypacker.Packet.load_handler(IEEE80211.Action,
	{
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_REQUEST: IEEE80211.Action.BlockAckRequest,
		CATEGORY_BLOCK_ACK_FACTOR + IEEE80211.Action.CODE_BLOCK_ACK_RESPONSE: IEEE80211.Action.BlockAckResponse
	}
)

"""Internet Group Management Protocol."""



class IGMP(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("maxresp", "B", 0),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("group", "4s", b"\x00" * 4)
	)

	# Convenient access for: group[_s]
	group_s = pypacker.get_property_ip4("group")

	def _update_fields(self):
		if self.sum_au_active and self._changed():
			self.sum = 0
			self.sum = checksum.in_cksum(pypacker.Packet.bin(self))

"""
Proof-of-concept Dshell plugin to detect INNUENDO DNS Channel

Based on the short marketing video (http://vimeo.com/115206626) the
INNUENDO DNS Channel relies on DNS to communicate with an authoritative
name server. The name server will respond with a base64 encoded TXT
answer. This plugin will analyze DNS TXT queries and responses to
determine if it matches the network traffic described in the video.
There are multiple assumptions (*very poor*) in this detection plugin
but serves as a proof-of-concept detector. This detector has not been
tested against authentic INNUENDO DNS Channel traffic.
"""


class DshellPlugin(DNSPlugin):
    """
    Proof-of-concept Dshell plugin to detect INNUENDO DNS Channel

    Usage: decode -d innuendo *.pcap
    """

    def __init__(self):
        super().__init__(
            name="innuendo-dns",
            description="proof-of-concept detector for INNUENDO DNS channel",
            bpf="port 53",
            author="primalsec",
            output=AlertOutput(label=__name__),
        )

    def dns_handler(self, conn, requests, responses):
        response = responses[-1]

        query = None
        answers = []

        if requests:
            request = requests[-1].pkt.highest_layer
            query = request.queries[-1]
            # DNS Question, extract query name if it is a TXT record request
            if query.type == dns.DNS_TXT:
                query = query.name_s

        if responses:
            for response in responses:
                rcode = response.rcode
                response = response.pkt.highest_layer
                # DNS Answer with data and no errors
                if rcode == dns.DNS_RCODE_NOERR and response.answers:
                    for answer in response.answers:
                        if answer.type == dns.DNS_TXT:
                            answers.append(answer.address)

        if query and answers:
            # assumption: INNUENDO will use the lowest level domain for C2
            # example: AAAABBBBCCCC.foo.bar.com -> AAAABBBBCCCC is the INNUENDO
            # data
            subdomain = query.split('.', 1)[0]

            # weak test based on video observation *very poor assumption*
            if subdomain.isupper():
                # check each answer in the TXT response
                for answer in answers:
                    try:
                        # INNUENDO DNS channel base64 encodes the response, check to see if
                        # it contains a valid base64 string  *poor assumption*
                        dummy = base64.b64decode(answer)

                        self.write('INNUENDO DNS Channel', query, '/', answer, **conn.info())

                        # here would be a good place to decrypt the payload (if you have the keys)
                        # decrypt_payload( answer )
                    except:
                        return None
                return conn, requests, responses

        return None

"""
Parse traffic to detect scanners based on connection to IPs that are rarely touched by others
"""

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='parse indegree',
            description='Parse traffic to detect scanners based on connection to IPs that are rarely touched by others',
            bpf='(tcp or udp)',
            author='dev195',
        )
        self.client_conns = {}
        self.server_conns = {}
        self.minhits = 3

    def connection_handler(self, conn):
        self.client_conns.setdefault(conn.clientip, set())
        self.server_conns.setdefault(conn.serverip, set())

        self.client_conns[conn.clientip].add(conn.serverip)
        self.server_conns[conn.serverip].add(conn.clientip)

    def postfile(self):
        for clientip, serverips in self.client_conns.items():
            target_count = len(serverips)
            S = min((len(self.server_conns[serverip]) for serverip in serverips))
            if S > 2 or target_count < 5:
                continue
            # TODO implement whitelist
            self.write("Scanning IP: {} / S score: {:.1f} / Number of records: {}".format(clientip, S, target_count))

"""Shared constants for IPv4 and IPv6."""

# Protocol numbers - http://www.iana.org/assignments/protocol-numbers
IP_PROTO_IP		= 0			# dummy for IP
IP_PROTO_HOPOPTS	= IP_PROTO_IP		# IPv6 hop-by-hop options
IP_PROTO_ICMP		= 1			# ICMP
IP_PROTO_IGMP		= 2			# IGMP
IP_PROTO_GGP		= 3			# gateway-gateway protocol
IP_PROTO_IPIP		= 4			# IP in IP
IP_PROTO_ST		= 5			# ST datagram mode
IP_PROTO_TCP		= 6			# TCP
IP_PROTO_CBT		= 7			# CBT
IP_PROTO_EGP		= 8			# exterior gateway protocol
IP_PROTO_IGP		= 9			# interior gateway protocol
IP_PROTO_BBNRCC		= 10			# BBN RCC monitoring
IP_PROTO_NVP		= 11			# Network Voice Protocol
IP_PROTO_PUP		= 12			# PARC universal packet
IP_PROTO_ARGUS		= 13			# ARGUS
IP_PROTO_EMCON		= 14			# EMCON
IP_PROTO_XNET		= 15			# Cross Net Debugger
IP_PROTO_CHAOS		= 16			# Chaos
IP_PROTO_UDP		= 17			# UDP
IP_PROTO_MUX		= 18			# multiplexing
IP_PROTO_DCNMEAS	= 19			# DCN measurement
IP_PROTO_HMP		= 20			# Host Monitoring Protocol
IP_PROTO_PRM		= 21			# Packet Radio Measurement
IP_PROTO_IDP		= 22			# Xerox NS IDP
IP_PROTO_TRUNK1		= 23			# Trunk-1
IP_PROTO_TRUNK2		= 24			# Trunk-2
IP_PROTO_LEAF1		= 25			# Leaf-1
IP_PROTO_LEAF2		= 26			# Leaf-2
IP_PROTO_RDP		= 27			# "Reliable Datagram" proto
IP_PROTO_IRTP		= 28			# Inet Reliable Transaction
IP_PROTO_TP		= 29			# ISO TP class 4
IP_PROTO_NETBLT		= 30			# Bulk Data Transfer
IP_PROTO_MFPNSP		= 31			# MFE Network Services
IP_PROTO_MERITINP	= 32			# Merit Internodal Protocol
IP_PROTO_SEP		= 33			# Sequential Exchange proto
IP_PROTO_3PC		= 34			# Third Party Connect proto
IP_PROTO_IDPR		= 35			# Interdomain Policy Route
IP_PROTO_XTP		= 36			# Xpress Transfer Protocol
IP_PROTO_DDP		= 37			# Datagram Delivery Proto
IP_PROTO_CMTP		= 38			# IDPR Ctrl Message Trans
IP_PROTO_TPPP		= 39			# TP++ Transport Protocol
IP_PROTO_IL		= 40			# IL Transport Protocol
IP_PROTO_IP6		= 41			# IPv6
IP_PROTO_SDRP		= 42			# Source Demand Routing
IP_PROTO_ROUTING	= 43			# IPv6 routing header
IP_PROTO_FRAGMENT	= 44			# IPv6 fragmentation header
IP_PROTO_RSVP		= 46			# Reservation protocol
IP_PROTO_GRE		= 47			# General Routing Encap
IP_PROTO_MHRP		= 48			# Mobile Host Routing
IP_PROTO_ENA		= 49			# ENA
IP_PROTO_ESP		= 50			# Encap Security Payload
IP_PROTO_AH		= 51			# Authentication Header
IP_PROTO_INLSP		= 52			# Integated Net Layer Sec
IP_PROTO_SWIPE		= 53			# SWIPE
IP_PROTO_NARP		= 54			# NBMA Address Resolution
IP_PROTO_MOBILE		= 55			# Mobile IP, RFC 2004
IP_PROTO_TLSP		= 56			# Transport Layer Security
IP_PROTO_SKIP		= 57			# SKIP
IP_PROTO_ICMP6		= 58			# ICMP for IPv6
IP_PROTO_NONE		= 59			# IPv6 no next header
IP_PROTO_DSTOPTS	= 60			# IPv6 destination Woptions
IP_PROTO_ANYHOST	= 61			# any host internal proto
IP_PROTO_CFTP		= 62			# CFTP
IP_PROTO_ANYNET		= 63			# any local network
IP_PROTO_EXPAK		= 64			# SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN	= 65			# Kryptolan
IP_PROTO_RVD		= 66			# MIT Remote Virtual Disk
IP_PROTO_IPPC		= 67			# Inet Pluribus Packet Core
IP_PROTO_DISTFS		= 68			# any distributed fs
IP_PROTO_SATMON		= 69			# SATNET Monitoring
IP_PROTO_VISA		= 70			# VISA Protocol
IP_PROTO_IPCV		= 71			# Inet Packet Core Utility
IP_PROTO_CPNX		= 72			# Comp Proto Net Executive
IP_PROTO_CPHB		= 73			# Comp Protocol Heart Beat
IP_PROTO_WSN		= 74			# Wang Span Network
IP_PROTO_PVP		= 75			# Packet Video Protocol
IP_PROTO_BRSATMON	= 76			# Backroom SATNET Monitor
IP_PROTO_SUNND		= 77			# SUN ND Protocol
IP_PROTO_WBMON		= 78			# WIDEBAND Monitoring
IP_PROTO_WBEXPAK	= 79			# WIDEBAND EXPAK
IP_PROTO_EON		= 80			# ISO CNLP
IP_PROTO_VMTP		= 81			# Versatile Msg Transport
IP_PROTO_SVMTP		= 82			# Secure VMTP
IP_PROTO_VINES		= 83			# VINES
IP_PROTO_TTP		= 84			# TTP
IP_PROTO_NSFIGP		= 85			# NSFNET-IGP
IP_PROTO_DGP		= 86			# Dissimilar Gateway Proto
IP_PROTO_TCF		= 87			# TCF
IP_PROTO_EIGRP		= 88			# EIGRP
IP_PROTO_OSPF		= 89			# Open Shortest Path First
IP_PROTO_SPRITERPC	= 90			# Sprite RPC Protocol
IP_PROTO_LARP		= 91			# Locus Address Resolution
IP_PROTO_MTP		= 92			# Multicast Transport Proto
IP_PROTO_AX25		= 93			# AX.25 Frames
IP_PROTO_IPIPENCAP	= 94			# yet-another IP encap
IP_PROTO_MICP		= 95			# Mobile Internet Ctrl
IP_PROTO_SCCSP		= 96			# Semaphore Comm Sec Proto
IP_PROTO_ETHERIP	= 97			# Ethernet in IPv4
IP_PROTO_ENCAP		= 98			# encapsulation header
IP_PROTO_ANYENC		= 99			# private encryption scheme
IP_PROTO_GMTP		= 100			# GMTP
IP_PROTO_IFMP		= 101			# Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI		= 102			# PNNI over IP
IP_PROTO_PIM		= 103			# Protocol Indep Multicast
IP_PROTO_ARIS		= 104			# ARIS
IP_PROTO_SCPS		= 105			# SCPS
IP_PROTO_QNX		= 106			# QNX
IP_PROTO_AN		= 107			# Active Networks
IP_PROTO_IPCOMP		= 108			# IP Payload Compression
IP_PROTO_SNP		= 109			# Sitara Networks Protocol
IP_PROTO_COMPAQPEER	= 110			# Compaq Peer Protocol
IP_PROTO_IPXIP		= 111			# IPX in IP
IP_PROTO_VRRP		= 112			# Virtual Router Redundancy
IP_PROTO_PGM		= 113			# PGM Reliable Transport
IP_PROTO_ANY0HOP	= 114			# 0-hop protocol
IP_PROTO_L2TP		= 115			# Layer 2 Tunneling Proto
IP_PROTO_DDX		= 116			# D-II Data Exchange (DDX)
IP_PROTO_IATP		= 117			# Interactive Agent Xfer
IP_PROTO_STP		= 118			# Schedule Transfer Proto
IP_PROTO_SRP		= 119			# SpectraLink Radio Proto
IP_PROTO_UTI		= 120			# UTI
IP_PROTO_SMP		= 121			# Simple Message Protocol
IP_PROTO_SM		= 122			# SM
IP_PROTO_PTP		= 123			# Performance Transparency
IP_PROTO_ISIS		= 124			# ISIS over IPv4
IP_PROTO_FIRE		= 125			# FIRE
IP_PROTO_CRTP		= 126			# Combat Radio Transport
IP_PROTO_CRUDP		= 127			# Combat Radio UDP
IP_PROTO_SSCOPMCE	= 128			# SSCOPMCE
IP_PROTO_IPLT		= 129			# IPLT
IP_PROTO_SPS		= 130			# Secure Packet Shield
IP_PROTO_PIPE		= 131			# Private IP Encap in IP
IP_PROTO_SCTP		= 132			# Stream Ctrl Transmission
IP_PROTO_FC		= 133			# Fibre Channel
IP_PROTO_RSVPIGN	= 134			# RSVP-E2E-IGNORE
IP_PROTO_RAW		= 255			# Raw IP packets
IP_PROTO_RESERVED	= IP_PROTO_RAW		# Reserved
IP_PROTO_MAX		= 255

"""
Outputs all IPv4/IPv6 traffic, and hex plus ascii with verbose flag
"""



logger = logging.getLogger("pypacker")


class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name='ip',
            description='IPv4/IPv6 plugin',
            bpf='ip or ip6',
            author='twp',
            output=AlertOutput(label=__name__),
        )

    def packet_handler(self, packet):
        self.write(**packet.info(), dir_arrow='->')
        # If verbose flag set, outputs packet contents in hex and ascii alongside packet info
        self.logger.info("\n" + dshell.util.hex_plus_ascii(packet.rawpkt))
        return packet


"""
Internet Protocol version 4.

RFC 791
"""

logger = logging.getLogger("pypacker")

# avoid references for performance reasons
in_cksum = checksum.in_cksum

# IP options
# http://www.iana.org/assignments/ip-parameters/ip-parameters.xml
IP_OPT_EOOL			= 0
IP_OPT_NOP			= 1
IP_OPT_SEC			= 2
IP_OPT_LSR			= 3
IP_OPT_TS			= 4
IP_OPT_ESEC			= 5
IP_OPT_CIPSO			= 6
IP_OPT_RR			= 7
IP_OPT_SID			= 8
IP_OPT_SSR			= 9
IP_OPT_ZSU			= 10
IP_OPT_MTUP			= 11
IP_OPT_MTUR			= 12
IP_OPT_FINN			= 13
IP_OPT_VISA			= 14
IP_OPT_ENCODE			= 15
IP_OPT_IMITD			= 16
IP_OPT_EIP			= 17
IP_OPT_TR			= 18
IP_OPT_ADDEXT			= 19
IP_OPT_RTRALT			= 20
IP_OPT_SDB			= 21
IP_OPT_UNASSGNIED		= 22
IP_OPT_DPS			= 23
IP_OPT_UMP			= 24
IP_OPT_QS			= 25
IP_OPT_EXP			= 30


# Type of service, RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT			= 0x00			# default
IP_TOS_LOWDELAY			= 0x10			# low delay
IP_TOS_THROUGHPUT		= 0x08			# high throughput
IP_TOS_RELIABILITY		= 0x04			# high reliability
IP_TOS_LOWCOST			= 0x02			# low monetary cost - XXX
IP_TOS_ECT			= 0x02			# ECN-capable transport
IP_TOS_CE			= 0x01			# congestion experienced

# IP precedence
IP_TOS_PREC_ROUTINE		= 0x00
IP_TOS_PREC_PRIORITY		= 0x20
IP_TOS_PREC_IMMEDIATE		= 0x40
IP_TOS_PREC_FLASH		= 0x60
IP_TOS_PREC_FLASHOVERRIDE	= 0x80
IP_TOS_PREC_CRITIC_ECP		= 0xA0
IP_TOS_PREC_INTERNETCONTROL	= 0xC0
IP_TOS_PREC_NETCONTROL		= 0xE0

# Fragmentation flags (ip_off)
IP_FRAG_RESERVED		= 0x4			# reserved
IP_FRAG_DONT			= 0x2			# don't fragment
IP_FRAG_MORE			= 0x1			# more fragments (not last frag)

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT			= 64			# default ttl, RFC 1122, RFC 1340
IP_TTL_MAX			= 255			# maximum ttl


class IP(pypacker.Packet):
	# version
	def __get_v(self):
		return self.v_hl >> 4

	def __set_v(self, value):
		self.v_hl = (value << 4) | (self.v_hl & 0xF)
	v = property(__get_v, __set_v)

	# Header length
	def __get_hl(self):
		return self.v_hl & 0x0F

	def __set_hl(self, value):
		self.v_hl = (self.v_hl & 0xF0) | value
	hl = property(__get_hl, __set_hl)

	def __get_flags(self):
		return (self.frag_off & 0xE000) >> 13

	def __set_flags(self, value):
		self.frag_off = (self.frag_off & ~0xE000) | (value << 13)
	fragment = property(__get_flags, __set_flags)

	def __get_offset(self):
		return self.frag_off & ~0xE000

	def __set_offset(self, value):
		self.frag_off = (self.frag_off & 0xE000) | value
	offset = property(__get_offset, __set_offset)

	def __get_dscp(self):
		return (self.tos & 0xFC) >> 2

	def __set_dscp(self, value):
		self.tos = (value << 2) | ((~0xFC) & self.tos)
	# Diff Services Codepoint
	dscp = property(__get_dscp, __set_dscp)

	def __get_ecn(self):
		return self.tos & 0x03

	def __set_ecn(self, value):
		self.tos = (self.tos & 0xFC) | value
	# Explicit Congestion Notification
	ecn = property(__get_ecn, __set_ecn)

	__hdr__ = (
		("v_hl", "B", 69, FIELD_FLAG_AUTOUPDATE, ((v, 0, 3), (hl, 4, 7))),  # = 0x45, hl = Header length (=hl*4 bytes)
		("tos", "B", 0, None, ((dscp, 0, 5), (ecn, 6, 7))),
		("len", "H", 20, FIELD_FLAG_AUTOUPDATE),  # Header + data length
		("id", "H", 0),
		("frag_off", "H", 0, None, ((fragment, 0, 2), (offset, 3, 15))),
		("ttl", "B", 64),
		("p", "B", IP_PROTO_TCP, FIELD_FLAG_IS_TYPEFIELD),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("src", "4s", b"\x00" * 4),
		("dst", "4s", b"\x00" * 4),
		("opts", None, triggerlist.TriggerList)
	)

	__handler__ = {
		IP_PROTO_ICMP: icmp.ICMP,
		IP_PROTO_IGMP: igmp.IGMP,
		IP_PROTO_TCP: tcp.TCP,
		IP_PROTO_UDP: udp.UDP,
		IP_PROTO_IP6: ip6.IP6,
		IP_PROTO_ESP: esp.ESP,
		IP_PROTO_PIM: pim.PIM,
		IP_PROTO_IPXIP: ipx.IPX,
		IP_PROTO_SCTP: sctp.SCTP,
		IP_PROTO_OSPF: ospf.OSPF
	}

	__update_dependants__ = {tcp.TCP, udp.UDP}

	def create_fragments(self, fragment_len=1480):
		"""
		Create fragment packets from this IP packet with max fragment_len bytes each.
		This will set the flags and offset values accordingly (see header field off).

		fragment_len -- max length of a fragment (IP header + payload)
		return -- fragment IP packets created from this packet
		"""
		if fragment_len % 8 != 0:
			raise Exception("fragment_len not multipe of 8 bytes: %r" % fragment_len)

		fragments = []
		length_ip_total = len(self.bin())
		payload = self.body_bytes
		length_ip_header = length_ip_total - len(payload)
		length_payload = length_ip_total - length_ip_header

		off = 0

		while off < length_payload:
			payload_sub = payload[off: off + fragment_len]

			ip_frag = IP(id=self.id, p=self.p, src=self.src, dst=self.dst)

			if length_payload - off > fragment_len:
				# More fragments follow
				ip_frag.flags = 0x1
			else:
				# Last fragment
				ip_frag.flags = 0x0

			ip_frag.offset = int(off / 8)
			ip_frag.body_bytes = payload_sub
			fragments.append(ip_frag)
			off += fragment_len

		return fragments

	# Convenient access for: src[_s], dst[_s]
	src_s = pypacker.get_property_ip4("src")
	dst_s = pypacker.get_property_ip4("dst")
	p_t = pypacker.get_property_translator("p", "IP_PROTO_")
	dscp_t = pypacker.get_property_translator("dscp", "IP_TOS_PREC_")
	fragment_t = pypacker.get_property_translator("fragment", "IP_FRAG")

	class IPOptSingle(pypacker.Packet):
		__hdr__ = (
			("type", "B", 0),
		)

		type_t = pypacker.get_property_translator("type", "IP_OPT_")

	class IPOptMulti(pypacker.Packet):
		"""
		len = total length (header + data)
		"""
		__hdr__ = (
			("type", "B", 0),
			("len", "B", 2),
		)

		type_t = pypacker.get_property_translator("type", "IP_OPT_")

		def _update_fields(self):
			self.len = len(self)

	def _dissect(self, buf):
		# 4 bits that specify the number of 32-bit words in the header
		total_header_length = (buf[0] & 0xF) << 2
		#logger.debug("Total length: %d" % total_header_length)
		options_length = total_header_length - 20  # total IHL - standard IP-len = options length

		#logger.debug("Optlen: %d" % options_length)
		if options_length > 0:
			# logger.debug("got some IP options: %s" % tl_opts)
			self.opts(buf[20: 20 + options_length], self._dissect_opts)
		elif options_length < 0:
			# Invalid header length: assume no options at all
			raise Exception("Invalid options length: %d" % options_length)

		# There are some cases where padding can not be identified on ethernet -> do it here (eg VSS shit trailer)
		return total_header_length, buf[9]

	__IP_OPT_SINGLE = {IP_OPT_EOOL, IP_OPT_NOP}

	@staticmethod
	def _dissect_opts(buf):
		"""Parse IP options and return them as list."""
		optlist = []
		i = 0
		p = None

		while i < len(buf):
			#logger.debug("Dissecting IP-option type %s" % buf[i])
			if buf[i] in IP.__IP_OPT_SINGLE:
				p = IP.IPOptSingle(type=buf[i])
				i += 1
			else:
				olen = buf[i + 1]
				#logger.debug("IPOptMulti")
				p = IP.IPOptMulti(type=buf[i], len=olen, body_bytes=buf[i + 2: i + olen])
				#logger.debug("body bytes: %s" % buf[i + 2: i + olen])
				i += olen		# typefield + lenfield + data-len
				#logger.debug("IPOptMulti 2")
			optlist.append(p)
		return optlist

	def _update_fields(self):
		self._update_higherlayer_id()

		if self.len_au_active:
			self.len = len(self)
		if self.v_hl_au_active:
			# Update header length. NOTE: needs to be a multiple of 4 Bytes.
			#logger.debug("Updating: %r" % self._packet)
			# options length need to be multiple of 4 Bytes
			self.hl = int(self.header_len / 4) & 0xF
		if self.sum_au_active:
			# Length changed so we have to recalculate checksum
			# reset checksum for recalculation,  mark as changed / clear cache
			self.sum = 0
			#logger.debug("Calculating sum over %d bytes (%r), current: %0X" % (
			#	len(self._pack_header()), self._pack_header(), self.sum))
			self.sum = in_cksum(self._pack_header())
			#logger.debug("Updated sum=%d, should be %0X" % (self.sum, in_cksum(self._pack_header())))

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, next))
		direction = 0
		if self.src == other.src and self.dst == other.dst:
			direction |= pypacker.Packet.DIR_SAME
		if self.src == other.dst and self.dst == other.src:
			direction |= pypacker.Packet.DIR_REV
		if direction == 0:
			direction = pypacker.Packet.DIR_UNKNOWN
		return direction

	def reverse_address(self):
		self.src, self.dst = self.dst, self.src

"""
Internet Printing Protocol (IPP)
https://www.rfc-editor.org/rfc/rfc2911
https://datatracker.ietf.org/doc/html/rfc2566
https://datatracker.ietf.org/doc/html/rfc2565

WARNING: may need HTTP reassemblation  before dissection
"""


"""
>>> Printer attributes
>> operations-supported

0x0000              reserved, not used
0x0001              reserved, not used
0x0002              Print-Job
0x0003              Print-URI
0x0004              Validate-Job
0x0005              Create-Job
0x0006              Send-Document
0x0007              Send-URI
0x0008              Cancel-Job
0x0009              Get-Job-Attributes
0x000A              Get-Jobs
0x000B              Get-Printer-Attributes
0x000C              Hold-Job
0x000D              Release-Job
0x000E              Restart-Job
0x000F              reserved for a future operation
0x0010              Pause-Printer
0x0011              Resume-Printer
0x0012              Purge-Jobs
0x0013-0x3FFF       reserved for future IETF standards track operations (see section 6.4)
0x4000-0x8FFF       reserved for vendor extensions (see section 6.4)


>>> Delimiter Tags
The following table specifies the values for the delimiter tags:

Tag Value (Hex)   Delimiter

0x00              reserved
0x01              operation-attributes-tag
0x02              job-attributes-tag
0x03              end-of-attributes-tag
0x04              printer-attributes-tag
0x05              unsupported-attributes-tag
0x06-0x0E         reserved for future delimiters
0x0F              reserved for future chunking-end-of-attributes-tag


>> the order of these
xxx-attributes-tags and xxx-attribute-sequences in the protocol MUST
be the same as in the model document, but the order of attributes
within each xxx-attribute-sequence MUST be unspecified


Model Document Group           xxx-attributes-sequence
---
Operation Attributes           operations-attributes-sequence
Job Template Attributes        job-attributes-sequence
Job Object Attributes          job-attributes-sequence
Unsupported Attributes         unsupported-attributes-sequence
Requested Attributes           job-attributes-sequence
Get-Job-Attributes)
Requested Attributes           printer-attributes-sequence
Get-Printer-Attributes)
Document Content               in a special position as described above


>>> Value Tags
The following table specifies the integer values for the value-tag:

Tag Value (Hex)  Meaning

0x20             reserved
0x21             integer
0x22             boolean
0x23             enum
0x24-0x2F        reserved for future integer types

0x30             octetString with an  unspecified format
0x31             dateTime
0x32             resolution
0x33             rangeOfInteger
0x34             reserved for collection (in the future)
0x35             textWithLanguage
0x36             nameWithLanguage
0x37-0x3F        reserved for future octetString types

0x40             reserved
0x41             textWithoutLanguage
0x42             nameWithoutLanguage
0x43             reserved
0x44             keyword
0x45             uri
0x46             uriScheme
0x47             charset
0x48             naturalLanguage

0x49             mimeMediaType
0x4A-0x5F        reserved for future character string types
"""

OPERATION_PRINTJOB			= 0x0002
OPERATION_PRINTURI			= 0x0003
OPERATION_VALIDATE_JOB			= 0x0004
OPERATION_CREATE_JOB			= 0x0005
OPERATION_GET_JOBS			= 0x000A
OPERATION_GET_PRINTER_ATTRIBUTES	= 0x000B

TAG_DEL_RESERVED		= 0x00
TAG_DEL_OP_ATTR_TAG		= 0x01
TAG_DEL_JOBATTR_TAG		= 0x02
TAG_DEL_END_OF_ATTR		= 0x03
TAG_DEL_PRINTER_ATTR_TAG	= 0x04
TAG_DEL_UNSUPPORTED_ATTR_TAG	= 0x05
#0x06-0x0E         reserved for future delimiters
#0x0F              reserved for future chunking-end-of-attributes-tag

TAGS_DELIMITER = {TAG_DEL_RESERVED, TAG_DEL_OP_ATTR_TAG, TAG_DEL_JOBATTR_TAG, TAG_DEL_END_OF_ATTR,
	TAG_DEL_PRINTER_ATTR_TAG, TAG_DEL_UNSUPPORTED_ATTR_TAG}

TAG_TYPE_BOOL			= 0x22
TAG_TYPE_KEYWORD		= 0x44
TAG_TYPE_URI			= 0x45
TAG_TYPE_CHARSET		= 0x47
TAG_TYPE_NAT_LANG		= 0x48
TAG_TYPE_TEXT_LANG		= 0x35
TAG_TYPE_NAME_LANG		= 0x36
TAG_TYPE_TEXT_NO_LANG		= 0x41
TAG_TYPE_NAME_NO_LANG		= 0x42
TAG_TYPE_MEDIA_MIME		= 0x49

"""
HTTP example:
POST / HTTP/1.1
Content-Length: 161
Content-Type: application/ipp
Date: Wed, 1 Jan 2000 21:50:58 GMT
Host: 1.2.3.4.1:631
User-Agent: CUPS/1.2.3 (Linux; x86_64) IPP/2.0
Expect: 100-continue

...
"""


class IPPBase(pypacker.Packet):
	class TypeNameContent(pypacker.Packet):
		__hdr__ = (
			("type", "B", 0),
			("name_len", "H", 0, FIELD_FLAG_AUTOUPDATE),
			("name", None, b""),
			("content_len", "H", 0, FIELD_FLAG_AUTOUPDATE)
		)

		def _dissect(self, buf):
			name_len = unpack_H(buf[1: 3])[0]
			self.name = buf[3: 3 + name_len]
			return 5 + name_len

		def _update_fields(self):
			if self._changed():
				if self.name_len_au_active:
					self.name_len = len(self.name)
				if self.content_len_au_active:
					self.content_len = len(self.body_bytes)

	class Attribute(pypacker.Packet):
		__hdr__ = (
			("parameter", None, triggerlist.TriggerList),
		)

		def get_name(self):
			# Avoid exception below
			if len(self.parameter) == 0 or type(self.parameter[0]) != TypeNameContent:
				return None

			# Assume TypeNameContent is used
			try:
				return self.parameter[0].body_bytes
			except:
				return None

	"""
	Attribute example Structure:

	//[operation-attributes-tag:1]
	[value-tag:2]
		name: [len:1][content:len]
		value: [len:1][content:len]
	[value-tag:2]
		name: [len:1][content:len]
		value: [len:1][content:len]
		// Member of same parent value-tag as long name-len is 0
		value:
			[value-tag:2]
			[name-len:1=0][name:name-len]
			[len:1][content:len]
	//[end-of-attributes-tag:1]
	"""

	@staticmethod
	def dissect_attributes(only_offsets=False):
		def dissect_attributes_sub(buf):
			"""buf -- Start direct after operation-attributes-tag"""
			#logger.debug("dissect_attributes_sub")
			attributes = []
			tncs = []
			off = 0
			value_tag = buf[off]
			value_tag_new = None

			while off < len(buf):
				name_len = unpack_H(buf[off + 1: off + 1 + 2])[0] # type:1, len:2, value:len
				content_len = unpack_H(buf[off + 1 + 2 + name_len: off + 1 + 2 + name_len + 2])[0]
				off_new = off + 1 + 2 + name_len + 2 + content_len
				#logger.debug(f"value_tag={value_tag:#x}, off={off}, name_len={name_len},
				#	 content_len={content_len}, off_new={off_new}")

				value_tag_new = None

				if off_new < len(buf):
					value_tag_new = buf[off_new]
					#logger.debug(f"value_tag_new={value_tag_new:X}")

				if not only_offsets:
					tnc = IPPBase.TypeNameContent(buf[off: off_new])
					tncs.append(tnc)

					if value_tag_new != value_tag:
						# End of Attribute reached, add all tncs
						attribute = IPPBase.Attribute()
						attribute.parameter.extend(tncs)
						attributes.append(attribute)
						tncs = []

				off = off_new

				if value_tag_new is None or value_tag_new in TAGS_DELIMITER:
					break

				value_tag = value_tag_new

			return off if only_offsets else attributes

		return dissect_attributes_sub


class IPPRequest(IPPBase):
	__hdr__ = (
		("version", "H", 0x0200),
		# The operation-attributes-tag MUST be the first tag delimiter, ...
		("operation", "H", OPERATION_GET_PRINTER_ATTRIBUTES),
		("req_id", "I", 1),

		("op_attr_tag", "B", TAG_DEL_OP_ATTR_TAG),
		("op_attr", None, triggerlist.TriggerList),

		# If the client is not supplying any Job Template attributes in the request,
		# the client SHOULD omit Group 2 rather than sending an empty group.
		("template_attr_tag", "B", None),
		("template_attr", None, triggerlist.TriggerList),

		# ... and the end-of-attributes-tag MUST be the last tag delimiter.
		("end_of_attribute_tag", "B", TAG_DEL_END_OF_ATTR),
		# If the operation has a document-content group,
		# the document data in that group MUST follow the end-of-attributes- tag.
		# -> Set document as body bytes
	)

	def _dissect(self, buf):
		#op_attr_len = dissect_attributes(only_offsets=True)(buf[9:])
		self.op_attr(buf[9: -1], IPPBase.dissect_attributes())

		return len(buf)


RESPONSE_STATUS_OK	= 0


class IPPResponse(IPPBase):
	__hdr__ = (
		("version", "H", 0x0200),
		("status", "H", RESPONSE_STATUS_OK),
		("req_id", "I", 1),
		("op_attr_tag", "B", TAG_DEL_OP_ATTR_TAG),
		("op_attr", None, triggerlist.TriggerList),
		("printer_attr_tag", "B", TAG_DEL_PRINTER_ATTR_TAG),
		("printer_attr", None, triggerlist.TriggerList),
		("end_of_attribute_tag", "B", TAG_DEL_END_OF_ATTR),
	)

	def _dissect(self, buf):
		off = 9
		op_attr_len = dissect_attributes(only_offsets=True)(buf[off:])
		#logger.debug(f"Response start 1: {buf[9: 20].tobytes()}, op_attr_len={op_attr_len}")
		self.op_attr(buf[off: off + op_attr_len], dissect_attributes())
		off += op_attr_len + 1
		#logger.debug(f"op_attr_len={op_attr_len}")
		printer_attr_len = dissect_attributes(only_offsets=True)(buf[off:])
		#logger.debug(f"Response start 2: {buf[9 + op_attr_len: 9 + op_attr_len + 20].tobytes()}")
		self.printer_attr(buf[off: off + printer_attr_len], dissect_attributes())

		return len(buf)
"""
Internetwork Packet Exchange (proprietary protocol)

https://www.novell.com/documentation/nw6p/?page=/documentation/nw6p/ipx_enu/data/hc1w6pvi.html
https://de.wikipedia.org/wiki/Internetwork_Packet_Exchange
"""


IPX_HDR_LEN = 30


class IPX(pypacker.Packet):
	__hdr__ = (
		("sum", "H", 0xFFFF),
		("len", "H", IPX_HDR_LEN),
		("tc", "B", 0),
		("pt", "B", 0),
		("dst", "12s", b""),
		("src", "12s", b"")
	)

"""
Packet interceptor using NFQueue

Requirements:
- CPython
- NFQUEUE target support in Kernel
- iptables
"""

logger = logging.getLogger("pypacker")

MSG_NO_NFQUEUE = "Could not load netfilter_queue library. See README.md for interceptor requirements."

netfilter = None # pylint: disable=invalid-name

try:
	# Load library
	nflib = utils.find_library("netfilter_queue")

	if nflib is None:
		raise RuntimeError()

	netfilter = ctypes.cdll.LoadLibrary(nflib)
except:
	logger.exception(MSG_NO_NFQUEUE)


class NfqQHandler(ctypes.Structure):
	pass


class NfnlHandle(ctypes.Structure):
	pass


nfnl_callback_ctype = ctypes.CFUNCTYPE(
	ctypes.c_int, *(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
)


class NfnlCallback(ctypes.Structure):
	_fileds_ = [("call", nfnl_callback_ctype),
		("data", ctypes.c_void_p),
		("attr_count", ctypes.c_uint16)
	]


class NfnlSubsysHandle(ctypes.Structure):
	_fields_ = [("nfilter_handler", ctypes.POINTER(NfnlHandle)),
		("subscriptions", ctypes.c_uint32),
		("subsys_id", ctypes.c_uint8),
		("cb_count", ctypes.c_uint8),
		("callback", ctypes.POINTER(NfnlCallback))
	]


class NfqHandle(ctypes.Structure):
	_fields_ = [("nfnlh", ctypes.POINTER(NfnlHandle)),
		("nfnlssh", ctypes.POINTER(NfnlSubsysHandle)),
		("qh_list", ctypes.POINTER(NfqQHandler))
	]


class NfqQHandle(ctypes.Structure):
	_fields_ = [("next", ctypes.POINTER(NfqQHandler)),
		("h", ctypes.POINTER(NfqHandle)),
		("id", ctypes.c_uint16),
		("cb", ctypes.POINTER(NfnlHandle)),
		("data", ctypes.c_void_p)
	]


class NfqData(ctypes.Structure):
	_fields_ = [("data", ctypes.POINTER(ctypes.c_void_p))]


class NfqnlMsgPacketHw(ctypes.Structure):
	_fields_ = [("hw_addrlen", ctypes.c_uint16),
		("_pad", ctypes.c_uint16),
		#############################
		("hw_addr", ctypes.c_uint8 * 8)]


class NfqnlMsgPacketHdr(ctypes.Structure):
	_fields_ = [("packet_id", ctypes.c_uint32),
		("hw_protocol", ctypes.c_uint16),
		("hook", ctypes.c_uint8)
	]


class Timeval(ctypes.Structure):
	_fields_ = [("tv_sec", ctypes.c_long),
		("tv_usec", ctypes.c_long)]


# Return netfilter netlink handler
nfnlh = netfilter.nfq_nfnlh
nfnlh.restype = ctypes.POINTER(NfnlHandle)
nfnlh.argtypes = (ctypes.POINTER(NfqHandle),)

# Return a file descriptor for the netlink connection associated with the
# given queue connection handle.
nfq_fd = netfilter.nfnl_fd
nfq_fd.restype = ctypes.c_int
nfq_fd.argtypes = (ctypes.POINTER(NfnlHandle),)

nfnl_rcvbufsiz = netfilter.nfnl_rcvbufsiz
nfnl_rcvbufsiz.restype = ctypes.c_int
nfnl_rcvbufsiz.argtypes = ctypes.POINTER(NfnlHandle), ctypes.c_uint

# This function obtains a netfilter queue connection handle
ll_open_queue = netfilter.nfq_open
ll_open_queue.restype = ctypes.POINTER(NfqHandle)

# This function closes the nfqueue handler and free associated resources.
close_queue = netfilter.nfq_close
close_queue.restype = ctypes.c_int
close_queue.argtypes = (ctypes.POINTER(NfqHandle),)

# Bind a nfqueue handler to a given protocol family.
bind_pf = netfilter.nfq_bind_pf
bind_pf.restype = ctypes.c_int
bind_pf.argtypes = ctypes.POINTER(NfqHandle), ctypes.c_uint16

# Unbind nfqueue handler from a protocol family.
unbind_pf = netfilter.nfq_unbind_pf
unbind_pf.restype = ctypes.c_int
unbind_pf.argtypes = ctypes.POINTER(NfqHandle), ctypes.c_uint16

# Creates a new queue handle, and returns it.
create_queue = netfilter.nfq_create_queue
create_queue.restype = ctypes.POINTER(NfqQHandler)
create_queue.argtypes = ctypes.POINTER(NfqHandle), ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p

# Removes the binding for the specified queue handle.
destroy_queue = netfilter.nfq_destroy_queue
destroy_queue.restype = ctypes.c_int
destroy_queue.argtypes = (ctypes.POINTER(NfqQHandler),)

# Triggers an associated callback for the given packet received from the queue.
handle_packet = netfilter.nfq_handle_packet
handle_packet.restype = ctypes.c_int
handle_packet.argtypes = ctypes.POINTER(NfqHandle), ctypes.c_char_p, ctypes.c_int

# nfqnl_config_mode
NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET = 0, 1, 2

# Sets the amount of data to be copied to userspace for each packet queued
# to the given queue.
#
# NFQNL_COPY_NONE - do not copy any data
# NFQNL_COPY_META - copy only packet metadata
# NFQNL_COPY_PACKET - copy entire packet
set_mode = netfilter.nfq_set_mode
set_mode.restype = ctypes.c_int
set_mode.argtypes = ctypes.POINTER(NfqQHandler), ctypes.c_uint8, ctypes.c_uint

# Sets the size of the queue in kernel. This fixes the maximum number
# of packets the kernel will store before internally before dropping
# upcoming packets.
set_queue_maxlen = netfilter.nfq_set_queue_maxlen
set_queue_maxlen.restype = ctypes.c_int
set_queue_maxlen.argtypes = ctypes.POINTER(NfqQHandler), ctypes.c_uint32

# Responses from hook functions.
NF_DROP, NF_ACCEPT, NF_STOLEN = 0, 1, 2
NF_QUEUE, NF_REPEAT, NF_STOP = 3, 4, 5
NF_MAX_VERDICT = NF_STOP

# Notifies netfilter of the userspace verdict for the given packet. Every
# queued packet _must_ have a verdict specified by userspace, either by
# calling this function, or by calling the nfq_set_verdict_mark() function.
# NF_DROP - Drop packet
# NF_ACCEPT - Accept packet
# NF_STOLEN - Don't continue to process the packet and not deallocate it.
# NF_QUEUE - Enqueue the packet
# NF_REPEAT - Handle the same packet
# NF_STOP -
# NF_MAX_VERDICT -
set_verdict = netfilter.nfq_set_verdict
set_verdict.restype = ctypes.c_int
set_verdict.argtypes = ctypes.POINTER(NfqQHandler), ctypes.c_uint32, ctypes.c_uint32, \
	ctypes.c_uint32, ctypes.c_char_p

# Return the metaheader that wraps the packet.
get_msg_packet_hdr = netfilter.nfq_get_msg_packet_hdr
get_msg_packet_hdr.restype = ctypes.POINTER(NfqnlMsgPacketHdr)
get_msg_packet_hdr.argtypes = (ctypes.POINTER(NfqData),)


# Get interface index
# Translation from interface index -> interface name: socket.if_indextoname(1)

# uint32_t nfq_get_physindev ( struct nfq_data *  nfad )
get_physindev = netfilter.nfq_get_physindev
get_physindev.restype = ctypes.c_uint32
get_physindev.argtypes = (ctypes.POINTER(NfqData),)

# uint32_t nfq_get_physoutdev ( struct nfq_data *  nfad )
get_physoutdev = netfilter.nfq_get_physoutdev
get_physoutdev.restype = ctypes.c_uint32
get_physoutdev.argtypes = (ctypes.POINTER(NfqData),)


# uint32_t  nfq_get_indev (struct nfq_data *nfad)
get_indev = netfilter.nfq_get_indev
get_indev.restype = ctypes.c_uint32
get_indev.argtypes = (ctypes.POINTER(NfqData),)

# uint32_t nfq_get_outdev ( struct nfq_data *  nfad )
get_outdev = netfilter.nfq_get_outdev
get_outdev.restype = ctypes.c_uint32
get_outdev.argtypes = (ctypes.POINTER(NfqData),)


# Retrieves the hardware address associated with the given queued packet.
# struct nfqnl_msg_packet_hw* nfq_get_packet_hw	(	struct nfq_data * 	nfad	 ) 	[read]
# Can be used to retrieve the source MAC address.
# The destination MAC address is not known until after POSTROUTING and a successful ARP request,
# so cannot currently be retrieved. (nfqueue documentation)
get_packet_hw = netfilter.nfq_get_packet_hw
get_packet_hw.restype = ctypes.POINTER(NfqnlMsgPacketHw)
get_packet_hw.argtypes = (ctypes.POINTER(NfqData),)

# Retrieve the payload for a queued packet.
get_payload = netfilter.nfq_get_payload
get_payload.restype = ctypes.c_int
get_payload.argtypes = ctypes.POINTER(NfqData), ctypes.POINTER(ctypes.c_void_p)


HANDLER = ctypes.CFUNCTYPE(
	#(struct NfqQHandler *qh, struct nfgenmsg *nfmsg, struct NfqData *nfa, void *data)
	None, *(ctypes.POINTER(NfqQHandler), ctypes.c_void_p, ctypes.POINTER(NfqData), ctypes.c_void_p)
)


def get_full_payload(nfa, ptr_packet):
	len_recv = get_payload(nfa, ctypes.byref(ptr_packet))
	data = ctypes.string_at(ptr_packet, len_recv)
	return len_recv, data


class UnableToBindException(Exception):
	def __init__(self, queue_id):
		self.queue_id = queue_id


class Interceptor():
	"""
	Packet interceptor. Allows MITM and filtering.
	Example config for iptables:
	$ iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
	Alternatively add nftables rule:
	$ nft add table inet pptable
	$ nft add chain inet pptable filter { type filter hook input priority 0; policy accept; }
	$ nft add rule inet pptable filter counter queue num 0-2
	"""
	QueueConfig = namedtuple("QueueConfig",
		["queue", "queue_id", "nfq_handle", "nfq_socket", "verdictthread", "handler"])

	def __init__(self, nfqueue_size=2048, rcvbufsiz=2048):
		"""
		nfqueue_size -- Sets the size of the queue in kernel. This fixes the maximum number of packets the
			kernel will store before internally before dropping upcoming packets.
		rcvbufsiz -- Sets the new size of the socket buffer. Use this setting to increase the socket buffer
			size if your system is reporting ENOBUFS errors.
		See: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/

		WARNING: Set nfqueue_size and rcvbufsiz to None (or lower values) if there are any problems on receiving
		"""
		self._netfilterqueue_configs = []
		self._is_running = False
		self._nfqueue_size = nfqueue_size
		self._rcvbufsiz = rcvbufsiz

	@staticmethod
	def verdict_trigger_cycler(recv_into, nfq_handle, obj):
		# Max IP packet size = 65535 bytes
		BUFSIZE = 70000
		rw_buffer = bytearray(BUFSIZE)
		rw_buffer_mview = memoryview(rw_buffer)

		rw_buffer_ctype = ctypes.c_char * BUFSIZE
		# Std python/ctype shared buffer
		rw_buffer_ctype_shared = rw_buffer_ctype.from_buffer(rw_buffer)

		try:
			while obj._is_running:
				bts_cnt = 0
				# Shouldn't add much overhead if there is no Exception
				try:
					bts_cnt = recv_into(rw_buffer_mview)
				except socket_timeout:
					#logger.debug("Socket timeout...")
					continue
				except OSError as e:
					# Ignore ENOBUFS errors, we can't handle this anyway
					# Alternative is to set NETLINK_NO_ENOBUFS socket option
					if e.errno == errno.ENOBUFS:
						logger.warning("Droppin' a packet, consider increasing receive buffer")
						continue
					raise e

				handle_packet(nfq_handle, rw_buffer_ctype_shared, bts_cnt)
		except OSError:
			# Eg "Bad file descriptor": started and nothing read yet
			#logger.error(ex)
			pass
		except Exception as ex:
			logger.error("Exception while reading: %r", ex)
		#finally:
		#	logger.debug("verdict_trigger_cycler finished, stopping Interceptor")
		#	obj.stop()

	def _setup_queue(self, queue_id, ctx, verdict_callback):
		def verdict_callback_ind(queue_handle, nfmsg, nfa, _data): # pylint: disable=too-many-locals,unused-argument
			packet_ptr = ctypes.c_void_p(0)
			pkg_hdr = get_msg_packet_hdr(nfa)
			packet_id = ntohl(pkg_hdr.contents.packet_id)
			linklayer_protoid = htons(pkg_hdr.contents.hw_protocol)

			len_recv, data = get_full_payload(nfa, packet_ptr) # pylint: disable=unused-variable
			hw_addr = None
			packet_hw = get_packet_hw(nfa)

			if packet_hw:
				# HW address not always present, eg DHCP discover -> offer...
				hw_info = packet_hw.contents
				hw_addrlen = ntohs(hw_info.hw_addrlen)
				hw_addr = ctypes.string_at(hw_info.hw_addr, size=hw_addrlen)

			if_idx_in = get_indev(nfa)
			if_idx_out = get_outdev(nfa)

			data_ret, verdict = data, NF_DROP

			try:
				data_ret, verdict = verdict_callback(hw_addr, linklayer_protoid, data, ctx, if_idx_in, if_idx_out)
			except Exception as ex:
				logger.warning("Verdict callback problem, packet will be dropped: %r", ex)

			set_verdict(queue_handle, packet_id, verdict, len(data_ret), ctypes.c_char_p(data_ret))

		nfq_handle = ll_open_queue()  # 2

		# This call is obsolete, Linux kernels from 3.8 onwards ignore it.
		#unbind_pf(nfq_handle, socket.AF_INET)
		#bind_pf(nfq_handle, socket.AF_INET)

		c_handler = HANDLER(verdict_callback_ind)
		queue = create_queue(nfq_handle, queue_id, c_handler, None)  # 1

		if not queue:
			raise UnableToBindException(queue_id)

		set_mode(queue, NFQNL_COPY_PACKET, 0xFFFF)

		nf = nfnlh(nfq_handle)
		fd = nfq_fd(nf)
		# fd, family, sockettype
		nfq_socket = socket.fromfd(fd, 0, 0)  # 3

		if self._nfqueue_size is not None:
			ret = set_queue_maxlen(queue, self._nfqueue_size)
			if ret == -1:
				logger.warning("Could not set queue_maxlen to %d", self._nfqueue_size)

		if self._rcvbufsiz is not None:
			ret = nfnl_rcvbufsiz(nf, self._rcvbufsiz)
			#logger.debug("Update rcvbufsiz: %d", ret)

		# TODO: Better solution to check for running state? Close socket and raise exception does not work in stop()
		nfq_socket.settimeout(1)

		thread = threading.Thread(
			target=Interceptor.verdict_trigger_cycler,
			args=[nfq_socket.recv_into, nfq_handle, self]
		)

		thread.start()

		qconfig = Interceptor.QueueConfig(
			queue=queue, queue_id=queue_id, nfq_handle=nfq_handle, nfq_socket=nfq_socket, verdictthread=thread,
			handler=c_handler
		)
		self._netfilterqueue_configs.append(qconfig)

	def start(self, verdict_callback, queue_ids, ctx=None):
		"""
		verdict_callback -- Signature: callback(hw_addr, linklayer_protoid, data, ctx, if_idx_in, if_idx_out): data, [NF_*]
			Interface index to name via: socket.if_indextoname(if_idx_in)
		queue_id --Que Ids placed using iptables/nftables like [id1, ...]
		ctx -- Context object given to verdict callback
		"""
		if self._is_running:
			return

		self._is_running = True

		try:
			for queue_id in queue_ids:
				# Setup queue and start producer threads
				self._setup_queue(queue_id, ctx, verdict_callback)
		except UnableToBindException as e:
			self.stop()
			raise e

	def stop(self):
		if not self._is_running:
			return

		# logger.debug("stopping Interceptor")
		self._is_running = False

		for qconfig in self._netfilterqueue_configs:
			try:
				destroy_queue(qconfig.queue)
				close_queue(qconfig.nfq_handle)
				qconfig.nfq_socket.close()
				#logger.debug("Joining verdict thread for queue %d", qconfig.queue_id)
				qconfig.verdictthread.join()
			except:
				# Don't mind, we can't do anything if something goes wrong here
				pass
		self._netfilterqueue_configs.clear()

"""
Internet Protocol version 6..for whoever needs it (:

RFC 2460
"""

logger = logging.getLogger("pypacker")

EXT_HDRS = {
	IP_PROTO_HOPOPTS,
	IP_PROTO_IP6,
	IP_PROTO_ROUTING,
	IP_PROTO_FRAGMENT,
	IP_PROTO_AH,
	IP_PROTO_ESP,
	IP_PROTO_DSTOPTS,
	# TODO: to be implemented
	# IP_PROTO_MOBILITY
	# IP_PROTO_NONEXT
}


class IP6(pypacker.Packet):
	__hdr__ = (
		("v_fc_flow", "I", 0x60000000),
		("dlen", "H", 0, FIELD_FLAG_AUTOUPDATE),  # Length: opts + data
		# Body handler type OR type of first extension hedader (opts header)
		("nxt", "B", 0),
		("hlim", "B", 255),  # hop limit
		("src", "16s", b"\x00" * 16),
		("dst", "16s", b"\x00" * 16),
		("opts", None, triggerlist.TriggerList)
	)

	def __get_v(self):
		return self.v_fc_flow >> 28

	def __set_v(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xF0000000) | (v << 28)
	v = property(__get_v, __set_v)

	def __get_fc(self):
		return (self.v_fc_flow >> 20) & 0xFF

	def __set_fc(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xFF00000) | (v << 20)
	fc = property(__get_fc, __set_fc)

	def __get_flow(self):
		return self.v_fc_flow & 0xFFFFF

	def __set_flow(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xFFFFF) | (v & 0xFFFFF)
	flow = property(__get_flow, __set_flow)

	# Convenient access for: src[_s], dst[_s]
	src_s = pypacker.get_property_ip6("src")
	dst_s = pypacker.get_property_ip6("dst")
	nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

	__handler__ = {
		IP_PROTO_ICMP6: icmp6.ICMP6,
		IP_PROTO_IGMP: igmp.IGMP,
		IP_PROTO_TCP: tcp.TCP,
		IP_PROTO_UDP: udp.UDP,
		IP_PROTO_ESP: esp.ESP,
		IP_PROTO_PIM: pim.PIM,
		IP_PROTO_IPXIP: ipx.IPX,
		IP_PROTO_SCTP: sctp.SCTP,
		IP_PROTO_OSPF: ospf.OSPF
	}

	__update_dependants__ = {tcp.TCP, udp.UDP, icmp6.ICMP6}

	def _dissect_opts(self, buf, collect_opts=True):
		off = 0
		opts = []
		type_current = self._type_opt
		#OPT_BASEHEADER_LEN = 8
		OPT_OFF_OLEN_SUB = 1
		OPT_OFF_TYPENXT_IP6 = 6
		OPTLEN_IP6 = 40

		while type_current in EXT_HDRS and off < len(buf):
			# Assume there is at least one option.
			# Different header structure for IP6 and sub-header
			# IP6: Total length = 8 + Payload length
			if type_current != IP_PROTO_IP6:
				# len 0 = 8 bytes
				optlen = 8 + buf[off + OPT_OFF_OLEN_SUB] * 8
				type_next = buf[off]
			else:
				# Fixed header length
				optlen = OPTLEN_IP6
				type_next = buf[off + OPT_OFF_TYPENXT_IP6]

			if collect_opts:
				opt = ext_hdrs_cls[type_current](buf[off: off + optlen])
				opts.append(opt)
			#logger.debug("Current type=%d, next type=%d, optlen=%d, %r" % (
			#	type_current, type_next, optlen, buf[off:off + optlen]))
			type_current = type_next
			off += optlen

		return (off, type_current) if not collect_opts else opts

	def _dissect(self, buf):
		BASEHEADER_LEN = 40  # Length: v_fc_flow -> dst
		TYPENXT_OFF = 6
		type_payload = buf[TYPENXT_OFF]
		optlen = 0
		#logger.debug("1st type: %r" % type_payload)

		# Parse options until type is an upper layer one
		if type_payload in EXT_HDRS:
			dlen = unpack_H(buf[4: 6])[0]
			# Used by tl
			self._type_opt = type_payload
			optlen, type_payload = self._dissect_opts(
				buf[BASEHEADER_LEN: BASEHEADER_LEN + dlen],
				collect_opts=False)
			#logger.debug("Handler will be=%r, optlen=%r" % (type_payload, optlen))
			self.opts(buf[BASEHEADER_LEN: BASEHEADER_LEN + optlen], self._dissect_opts)

		return BASEHEADER_LEN + optlen, type_payload

	def _update_fields(self):
		if self.dlen_au_active:
			self.dlen = len(self.opts.bin()) + len(self.body_bytes)
		# Set type value in nxt OR in last opts element (if present)
		# Updating is a bit more complicated so we can't use FIELD_FLAG_IS_TYPEFIELD
		# idval is None if body handler is None
		# logger.debug("handler %r -> %r", self.__class__, self.higher_layer.__class__)
		idval = pypacker.Packet.get_id_for_handlerclass(self.__class__, self.higher_layer.__class__)
		#logger.debug("nxt will be %r", idval)

		if idval is not None:
			if len(self.opts) == 0:
				self.nxt = idval
			else:
				# problem if opts[-1] is immutable
				try:
					self.opts[-1].nxt = idval
				except:
					pass

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, next))
		if self.src == other.src and self.dst == other.dst:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		if self.src == other.dst and self.dst == other.src:
			return pypacker.Packet.DIR_REV
		return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.src, self.dst = self.dst, self.src

	class IP6OptsHeader(pypacker.Packet):
		__hdr__ = (
			("nxt", "B", 0),  # next extension header protocol
			("len", "B", 0),  # option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
			("opts", None, triggerlist.TriggerList)
		)

		nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

		@staticmethod
		def parse_opts(buf):
			off = 0
			opts = []

			while off < len(buf):
				opt_type = buf[off]
				#logger.debug("IP6OptsHeader: type: %d" % opt_type)

				# http://tools.ietf.org/html/rfc2460#section-4.2
				# PAD1 option: no length or data field
				if opt_type == 1:
					#logger.debug("IP6OptionPad")
					opt = IP6.IP6OptsHeader.IP6OptionPad(buf[off: off + 2])
					off += 2  # type field + length field
				else:
					#logger.debug("IP6Option")
					opt_len = buf[off + 1]
					opt = IP6.IP6OptsHeader.IP6Option(buf[off: off + 2 + opt_len])
					off += 2 + opt_len  # type field + length field + dat

				opts.append(opt)
			#logger.debug("Returning opts: %r" % opts)
			return opts

		def _dissect(self, buf):
			hlen = 8 + buf[1] * 8
			OPTS_OFF = 2

			self.opts(buf[OPTS_OFF: hlen], IP6.IP6OptsHeader.parse_opts)
			return hlen

		class IP6Option(pypacker.Packet):
			__hdr__ = (
				("type", "B", 0),
				("len", "B", 0)
			)

		class IP6OptionPad(pypacker.Packet):
			__hdr__ = (
				("type", "B", 0),
			)

		class IP6HopOptsHeader(pypacker.Packet):
			__hdr__ = (
				("nxt", "B", 0),  # next extension header protocol
				("len", "B", 0),  # option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
				("opts", None, triggerlist.TriggerList)
			)

			nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

			def _dissect(self, buf):
				# logger.debug("IP6HopOptsHeader parsing")
				return IP6.IP6OptsHeader._dissect(self, buf)

		class IP6RoutingHeader(pypacker.Packet):
			__hdr__ = (
				("nxt", "B", 0),  # next extension header protocol
				("len", "B", 0),  # extension data length in 8 octect units (ignoring first 8 octets) (<= 46 for type 0)
				("type", "B", 0),  # routing type (currently, only 0 is used)
				("segs_left", "B", 0),  # remaining segments in route, until destination (<= 23)
				("lastentry", "B", 0),
				("flags", "B", 0),
				("tag", "H", 0),
				("addresses", None, triggerlist.TriggerList)
			)

			nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

			def __get_sl_bits(self):
				return self.rsvd_sl_bits & 0xFFFFFF

			def __set_sl_bits(self, v):
				self.rsvd_sl_bits = (self.rsvd_sl_bits & ~0xFFFFF) | (v & 0xFFFFF)

			sl_bits = property(__get_sl_bits, __set_sl_bits)

			def _dissect(self, buf):
				hdr_size = 8
				addr_size = 16
				num_addresses = int(buf[1] / 2)
				buf_opts = buf[hdr_size: hdr_size + num_addresses * addr_size]
				self.addresses(buf_opts,
					lambda buf: [buf[i * addr_size: i * addr_size + addr_size].tobytes() for i in range(num_addresses)])

				return hdr_size + num_addresses * addr_size

		class IP6FragmentHeader(pypacker.Packet):
			__hdr__ = (
				("nxt", "B", 0),			# next extension header protocol
				("resv", "B", 0),			# reserved, set to 0
				("frag_off_resv_m", "H", 0),		# frag offset (13 bits), reserved zero (2 bits), More frags flag
				("id", "I", 0)				# fragments id
			)

			nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

			def __get_frag_off(self):
				return self.frag_off_resv_m >> 3

			def __set_frag_off(self, v):
				self.frag_off_resv_m = (self.frag_off_resv_m & ~0xFFF8) | (v << 3)
			frag_off = property(__get_frag_off, __set_frag_off)

			def __get_m_flag(self):
				return self.frag_off_resv_m & 1

			def __set_m_flag(self, v):
				self.frag_off_resv_m = (self.frag_off_resv_m & ~0xFFFE) | v
			m_flag = property(__get_m_flag, __set_m_flag)

		class IP6ESPHeader(pypacker.Packet):
			def _dissect(self, buf):
				raise NotImplementedError("ESP extension headers are not supported.")

		class IP6AHHeader(pypacker.Packet):
			__hdr__ = (
				("nxt", "B", 0),			 # next extension header protocol
				("len", "B", 0),			 # length of header in 4 octet units (ignoring first 2 units)
				("resv", "H", 0),			 # reserved, 2 bytes of 0
				("spi", "I", 0),			 # SPI security parameter index
				("seq", "I", 0)				 # sequence no.
			)

			nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

		class IP6DstOptsHeader(pypacker.Packet):
			__hdr__ = (
				("nxt", "B", 0),  # next extension header protocol
				("len", "B", 0),  # option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
				("opts", None, triggerlist.TriggerList)
			)

			def _dissect(self, buf):
				# logger.debug("IP6DstOptsHeader parsing")
				IP6.IP6OptsHeader._dissect(self, buf)

			nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")


# Needs to be put here and not IP6 bc: IP6 is not known at class definition time
ext_hdrs_cls = {
	IP_PROTO_IP6: IP6,
	IP_PROTO_HOPOPTS: IP6.IP6OptsHeader.IP6HopOptsHeader,
	IP_PROTO_ROUTING: IP6.IP6OptsHeader.IP6RoutingHeader,
	IP_PROTO_FRAGMENT: IP6.IP6OptsHeader.IP6FragmentHeader,
	IP_PROTO_ESP: IP6.IP6OptsHeader.IP6ESPHeader,
	IP_PROTO_AH: IP6.IP6OptsHeader.IP6AHHeader,
	IP_PROTO_DSTOPTS: IP6.IP6OptsHeader.IP6DstOptsHeader
	# IP_PROTO_MOBILITY:
	# IP_PROTO_NONEXT:
}

    
####################################################################
#
#
#           DSHELL I SCRIPTS END
#
#
###################################################################
    

####################################################################
#
#
#           DSHELL J THROUGH L SCRIPTS START
#
#
###################################################################


"""Generate JA3 fingerprints from PCAPs using Python."""


__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings2@gmail.com"


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    for timestamp, buf in pcap:
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)

            record = {"source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "ja3": ja3,
                      "ja3_digest": md5(ja3.encode()).hexdigest(),
                      "timestamp": timestamp,
                      "client_hello_pkt": binascii.hexlify(tcp.data).decode('utf-8')}
            results.append(record)

    return results


def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=False, help=help_text)
    help_text = "Print packet related data for research (json only)"
    parser.add_argument("-r", "--research", required=False, action="store_true",
                        default=False, help=help_text)
    args = parser.parse_args()

    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e_pcap:
            try:
                fp.seek(0, os.SEEK_SET)
                capture = dpkt.pcapng.Reader(fp)
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port)

    if args.json:
        if not args.research:
            def remove_items(x):
                del x['client_hello_pkt']
            list(map(remove_items,output))
        output = json.dumps(output, indent=4, sort_keys=True)
        print(output)
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
        main()



"""Generate JA3 fingerprints from PCAPs using Python."""


__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings@salesforce.com"


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    for timestamp, buf in pcap:
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)

            record = {"source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "ja3": ja3,
                      "ja3_digest": md5(ja3.encode()).hexdigest(),
                      "timestamp": timestamp}
            results.append(record)

    return results


def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=True, help=help_text)
    args = parser.parse_args()

    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e_pcap:
            try:
                fp.seek(0, os.SEEK_SET)
                capture = dpkt.pcapng.Reader(fp)
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port)

    if args.json:
        output = json.dumps(output, indent=4, sort_keys=True)
        print(output)
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
        main()



"""Generate JA3 fingerprints from PCAPs using Python."""


__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.1"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings2@gmail.com"


SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def process_extensions(server_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(server_handshake, "extensions"):
        # Needed to preserve commas on the join
        return [""]

    exts = list()
    for ext_val, ext_data in server_handshake.extensions:
        exts.append(ext_val)

    results = list()
    results.append("-".join([str(x) for x in exts]))
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    for timestamp, buf in pcap:
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            server_hello = bytearray(record.data)
            if server_hello[0] != 2:
                # We only want server HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                # Still not the HELLO
                continue

            server_handshake = handshake.data
            ja3 = [str(server_handshake.version)]

            # Cipher Suites (16 bit values)
            if LooseVersion(dpkt.__version__) <= LooseVersion('1.9.1'):
                ja3.append(str(server_handshake.cipher_suite))
            else:
                ja3.append(str(server_handshake.ciphersuite.code))
            ja3 += process_extensions(server_handshake)
            ja3 = ",".join(ja3)

            record = {"source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "ja3": ja3,
                      "ja3_digest": md5(ja3.encode()).hexdigest(),
                      "timestamp": timestamp}
            results.append(record)

    return results


def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=False, help=help_text)
    args = parser.parse_args()

    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e_pcap:
            try:
                fp.seek(0, os.SEEK_SET)
                capture = dpkt.pcapng.Reader(fp)
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port)

    if args.json:
        output = json.dumps(output, indent=4, sort_keys=True)
        print(output)
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3S: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
        main()



"""Generate JA3 fingerprints from PCAPs using Python."""


__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.1"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings2@gmail.com"


SSL_PORT = 443
TLS_HANDSHAKE = 22


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def process_extensions(server_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(server_handshake, "extensions"):
        # Needed to preserve commas on the join
        return [""]

    exts = list()
    for ext_val, ext_data in server_handshake.extensions:
        exts.append(ext_val)

    results = list()
    results.append("-".join([str(x) for x in exts]))
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    for timestamp, buf in pcap:
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            server_hello = bytearray(record.data)
            if server_hello[0] != 2:
                # We only want server HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSServerHello):
                # Still not the HELLO
                continue

            server_handshake = handshake.data
            ja3 = [str(server_handshake.version)]

            # Cipher Suites (16 bit values)
            if LooseVersion(dpkt.__version__) <= LooseVersion('1.9.1'):
                ja3.append(str(server_handshake.cipher_suite))
            else:
                ja3.append(str(server_handshake.ciphersuite.code))
            ja3 += process_extensions(server_handshake)
            ja3 = ",".join(ja3)

            record = {"source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "ja3": ja3,
                      "ja3_digest": md5(ja3.encode()).hexdigest(),
                      "timestamp": timestamp}
            results.append(record)

    return results


def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=False, help=help_text)
    args = parser.parse_args()

    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e_pcap:
            try:
                fp.seek(0, os.SEEK_SET)
                capture = dpkt.pcapng.Reader(fp)
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port)

    if args.json:
        output = json.dumps(output, indent=4, sort_keys=True)
        print(output)
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3S: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
        main()
"""
This output module converts plugin output into JSON
"""


class JSONOutput(Output):
    """
    Converts arguments for every write into JSON
    Can be called with ensure_ascii=True to pass flag on to the json module.
    """
    _DEFAULT_FORMAT = "%(jsondata)s\n"
    _DESCRIPTION = "JSON format output"

    def __init__(self, *args, **kwargs):
        self.ensure_ascii = kwargs.get('ensure_ascii', False)
        super().__init__(*args, **kwargs)

    def write(self, *args, **kwargs):
        if self.extra:
            # JSONOutput does not make use of the --extra flag, so disable it
            # before printing output
            self.extra = False
        if args and 'data' not in kwargs:
            kwargs['data'] = self.delimiter.join(map(str, args))
        jsondata = json.dumps(kwargs, ensure_ascii=self.ensure_ascii, default=self.json_default)
        super().write(jsondata=jsondata)

    def json_default(self, obj):
        """
        JSON serializer for objects not serializable by default json code
        https://stackoverflow.com/a/22238613
        """
        if isinstance(obj, datetime):
            serial = obj.strftime(self.timeformat)
            return serial
        if isinstance(obj, bytes):
            serial = repr(obj)
            return serial
        if isinstance(obj, (Connection, Blob, Packet)):
            serial = obj.info()
            return serial
        raise TypeError ("Type not serializable ({})".format(str(type(obj))))

obj = JSONOutput

