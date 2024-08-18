"""
A collection of useful utilities used in several plugins and libraries.
"""

import os
import string


def xor(xinput, key):
    """
    Xor an input string with a given character key.

    Arguments:
        input:  plain text input string
        key:    xor key
    """
    output = ''.join([chr(ord(c) ^ key) for c in xinput])
    return output


def get_data_path():
    dpath = os.path.dirname(__file__)
    return os.path.sep.join((dpath, 'data'))


def get_plugin_path():
    dpath = os.path.dirname(__file__)
    return os.path.sep.join((dpath, 'plugins'))


def get_output_path():
    dpath = os.path.dirname(__file__)
    return os.path.sep.join((dpath, 'output'))


def decode_base64(intext, alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', padchar='='):
    """
    Decodes a base64-encoded string, optionally using a custom alphabet.

    Arguments:
        intext:     input plaintext string
        alphabet:   base64 alphabet to use
        padchar:    padding character
    """
    # Build dictionary from alphabet
    alphabet_index = {}
    for i, c in enumerate(alphabet):
        if c in alphabet_index:
            raise ValueError("'{}' used more than once in alphabet".format(c))
        alphabet_index[c] = i
    alphabet_index[padchar] = 0

    alphabet += padchar

    outtext = ''
    intext = intext.rstrip('\n')

    i = 0
    while i < len(intext) - 3:
        if (
            intext[i] not in alphabet
            or intext[i + 1] not in alphabet
            or intext[i + 2] not in alphabet
            or intext[i + 3] not in alphabet
        ):
            raise KeyError("Non-alphabet character in encoded text.")
        val = alphabet_index[intext[i]] * 262144
        val += alphabet_index[intext[i + 1]] * 4096
        val += alphabet_index[intext[i + 2]] * 64
        val += alphabet_index[intext[i + 3]]
        i += 4
        for factor in [65536, 256, 1]:
            outtext += chr(int(val / factor))
            val = val % factor

    return outtext


def printable_text(intext, include_whitespace=True):
    """
    Replaces non-printable characters with dots.

    Arguments:
        intext:     input plaintext string
        include_whitespace (bool):  set to False to mark whitespace characters
                                    as unprintable
    """
    printable = string.ascii_letters + string.digits + string.punctuation
    if include_whitespace:
        printable += string.whitespace

    if isinstance(intext, bytes):
        intext = intext.decode("ascii", errors="replace")

    outtext = [c if c in printable else '.' for c in intext]
    outtext = ''.join(outtext)

    return outtext


def hex_plus_ascii(data, width=16, offset=0):
    """
    Converts a data string into a two-column hex and string layout,
    similar to tcpdump with -X

    Arguments:
        data:   incoming data to format
        width:  width of the columns
        offset: offset output from the left by this value
    """
    output = ""
    for i in range(0, len(data), width):
        s = data[i:i + width]
        if isinstance(s, bytes):
            outhex = ' '.join(["{:02X}".format(x) for x in s])
        else:
            outhex = ' '.join(["{:02X}".format(ord(x)) for x in s])
        outstr = printable_text(s, include_whitespace=False)
        outstr = "{:08X}  {:49}  {}\n".format(i + offset, outhex, outstr)
        output += outstr
    return output


def gen_local_filename(path, origname):
    """
    Generates a local filename based on the original. Automatically adds a
    number to the end, if file already exists.

    Arguments:
        path:       output path for file
        origname:   original name of the file to transform
    """

    tmp = origname.replace("\\", "_")
    tmp = tmp.replace("/", "_")
    tmp = tmp.replace(":", "_")
    localname = ''
    for c in tmp:
        if ord(c) > 32 and ord(c) < 127:
            localname += c
        else:
            localname += "%%%02X" % ord(c)
    localname = os.path.join(path, localname)
    postfix = ''
    i = 0
    while os.path.exists(localname + postfix):
        i += 1
        postfix = "_{:04d}".format(i)
    return localname + postfix


def human_readable_filesize(bytecount):
    """
    Converts the raw byte counts into a human-readable format
    https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size/1094933#1094933
    """
    for unit in ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB'):
        if abs(bytecount) < 1024.0:
            return "{:3.2f} {}".format(bytecount, unit)
        bytecount /= 1024.0
    return "{:3.2f} {}".format(bytecount, "YB")


# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import tempfile

import pyproject_hooks

from . import ProjectBuilder
from ._compat import importlib
from ._types import StrPath, SubprocessRunner
from .env import DefaultIsolatedEnv


def _project_wheel_metadata(builder: ProjectBuilder) -> importlib.metadata.PackageMetadata:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = pathlib.Path(builder.metadata_path(tmpdir))
        return importlib.metadata.PathDistribution(path).metadata


def project_wheel_metadata(
    source_dir: StrPath,
    isolated: bool = True,
    *,
    runner: SubprocessRunner = pyproject_hooks.quiet_subprocess_runner,
) -> importlib.metadata.PackageMetadata:
    """
    Return the wheel metadata for a project.

    Uses the ``prepare_metadata_for_build_wheel`` hook if available,
    otherwise ``build_wheel``.

    :param source_dir: Project source directory
    :param isolated: Whether or not to run invoke the backend in the current
                     environment or to create an isolated one and invoke it
                     there.
    :param runner: An alternative runner for backend subprocesses
    """

    if isolated:
        with DefaultIsolatedEnv() as env:
            builder = ProjectBuilder.from_isolated_env(
                env,
                source_dir,
                runner=runner,
            )
            env.install(builder.build_system_requires)
            env.install(builder.get_requires_for_build('wheel'))
            return _project_wheel_metadata(builder)
    else:
        builder = ProjectBuilder(
            source_dir,
            runner=runner,
        )
        return _project_wheel_metadata(builder)


__all__ = [
    'project_wheel_metadata',
]


# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Utility functions, primarily written for Linux based OS.
"""
import subprocess
import re
import os
import logging
import math
import ipaddress
import collections

#from pypacker import pypacker as pypacker
from pypacker import pypacker


logger = logging.getLogger("pypacker")

try:
	import netifaces
except ImportError:
	logger.warning("Couldn't load netifaces, some utils won't work")

log = math.log
mac_bytes_to_str = pypacker.mac_bytes_to_str


def switch_wlan_channel(iface, channel, shutdown_prior=False):
	"""
	Switch wlan channel to channel.
	Requirements: ifconfig, iwconfig

	iface -- interface name
	channel -- channel numer to be set as number
	shutdown_prior -- shut down interface prior to setting channel
	"""
	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)

	cmd_call = ["iwconfig", iface, "channel", "%d" % channel]
	subprocess.check_call(cmd_call)

	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


WLAN_MODE_MANAGED	= 0
WLAN_MODE_MONITOR	= 1
WLAN_MODE_UNKNOWN	= 2

_MODE_STR_INT_TRANSLATE = {
	b"managed": WLAN_MODE_MANAGED,
	b"monitor": WLAN_MODE_MONITOR,
	b"": WLAN_MODE_UNKNOWN
}

PATTERN_MODE	= re.compile(br"Mode:(\w+) ")


def get_wlan_mode(iface):
	"""
	return -- [MODE_MANAGED | MODE_MONITOR | MODE_UNKNOWN]
	"""
	cmd_call = ["iwconfig", iface]
	output = subprocess.check_output(cmd_call)
	match = PATTERN_MODE.search(output)

	found_str = match.group(1).lower()
	return _MODE_STR_INT_TRANSLATE.get(found_str, WLAN_MODE_UNKNOWN)


def is_interface_up(iface):
	"""
	Requirements: ifconfig

	return -- [True | False]
	"""
	cmd_call = ["ifconfig"]
	pattern_up = re.compile(b"^" + bytes(iface, "UTF-8") + b": flags=", re.MULTILINE)
	output = subprocess.check_output(cmd_call)
	return pattern_up.search(output) is not None


PATTERN_MODE = re.compile(br"wiphy (\d+)")


def get_phy_name(iface_wifi):
	"""
	Requirements: iw

	return -- phy_name
	"""
	cmd_call = ["iw", "dev", iface_wifi, "info"]
	output = subprocess.check_output(cmd_call)
	match = PATTERN_MODE.search(output)
	phy_dev = "phy" + match.group(1).decode("UTF-8")
	#logger.debug(f"Phy dev translation: {iface_wifi}={phy_dev}")
	return phy_dev


def set_wifi_monitor_config(iface_wifi):
	"""
	Try various settings to improve monitor mode. Might not always work.
	Requirements: iw

	Additional manual configs:
	iw dev | grep -P 'phy|Interface'
	iw phy phy3 set retry short 1 long 1
	iw phy phy3 set rts off
	"""
	phy_dev = get_phy_name(iface_wifi)

	# Alternative via iwconfig
	# cmd_call = ["iwconfig", iface, "retry", "0"]

	for cmd_str in [f"iw phy {phy_dev} set retry short 1 long 1", f"iw phy {phy_dev} set rts off"]:
		try:
			subprocess.check_call(cmd_str.split(" "))
		except:
			# Ignore, depends on driver capabilities
			pass


def set_interface_mode(iface, monitor_active=None, mtu=None, state_active=None):
	"""
	Configure an interface, primarily for wifi monitor mode
	Requirements: ifconfig, iwconfig

	monitor_active -- activate/deactivate monitor mode (only for wlan interfaces)
	state_active -- set interface state
	"""
	initial_state_up = is_interface_up(iface)

	if monitor_active is not None:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)
		mode = "monitor" if monitor_active else "managed"
		cmd_call = ["iwconfig", iface, "mode", mode]
		subprocess.check_call(cmd_call)
		set_wifi_monitor_config(iface)

	if type(mtu) is int:
		cmd_call = ["ifconfig", iface, "mtu", "%d" % mtu]
		subprocess.check_call(cmd_call)

	if state_active or initial_state_up:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


def is_interface_present(iface_name):
	try:
		netifaces.ifaddresses(iface_name)
		return True
	except ValueError:
		# Raised if interface is not present
		return False


def set_interface_state(iface_name, state_active=True):
	"""
	Requirements: ip
	"""
	state_str = "up" if state_active else "down"
	output = subprocess.getoutput("ip link set dev %s %s" % (iface_name, state_str))
	logger.info(output)


PROG_CHANNEL = re.compile(br"Channel ([\d]+) :")


def get_available_wlan_channels(iface):
	"""
	Requirements: iwlist

	return -- channels as integer list
	"""
	cmd_call = ["iwlist", iface, "channel"]
	output = subprocess.check_output(cmd_call)
	# logger.debug("iwlist output: %r", output)

	return [int(ch) for ch in PROG_CHANNEL.findall(output)]


def set_ethernet_address(iface, ethernet_addr):
	"""
	iface -- interface name
	ethernet_addr -- Ethernet address like "AA:BB:CC:DD:EE:FF"
	"""
	initial_state_up = is_interface_up(iface)
	cmd_call = ["ifconfig", iface, "down"]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "hw", "ether", ethernet_addr]
	subprocess.check_call(cmd_call)

	if initial_state_up:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


MAC_VENDOR = {}
PROG_MACVENDOR = re.compile(r"([\w\-]{8,8})   \(hex\)\t\t(.+)")
PROG_MACVENDOR_STRIPPED = re.compile(r"(.{6,6}) (.+)")
DIR_CURRENT = os.path.dirname(os.path.realpath(__file__)) + "/"
FILE_OUI = DIR_CURRENT + "oui.txt"
FILE_OUI_STRIPPED = DIR_CURRENT + "oui_stripped.txt"


def _convert():
	"""
	Convert oui file
	return -- True on success, False otherwise
	"""
	# logger.debug("loading oui file %s", FILE_OUI)

	try:
		with open(FILE_OUI, "r", encoding="utf-8") as fh_read:
			for line in fh_read:
				hex_vendor = PROG_MACVENDOR.findall(line)

				if len(hex_vendor) > 0:
					# logger.debug(hex_vendor)
					MAC_VENDOR[hex_vendor[0][0].replace("-", "")] = hex_vendor[0][1]
	except:
		# logger.debug("no oui file present -> nothing to convert")
		return False

	try:
		with open(FILE_OUI_STRIPPED, "w", encoding="utf-8") as fh_write:
			for mac, descr in MAC_VENDOR.items():
				fh_write.write("%s %s\n" % (mac, descr))
	except Exception as ex:
		logger.warning("could not create stripped oui file %r", ex)
		return False
	return True


def _load_mac_vendor():
	"""
	Load oui.txt containing mac->vendor mappings into MAC_VENDOR dictionary.
	See http://standards.ieee.org/develop/regauth/oui/oui.txt
	"""
	if not os.path.isfile(FILE_OUI_STRIPPED):
		success = False

		if os.path.isfile(FILE_OUI):
			success = _convert()

		if not success:
			return

	# logger.debug("loading stripped oui file %s", FILE_OUI_STRIPPED)

	try:
		with open(FILE_OUI_STRIPPED, "r", encoding="utf-8") as fh_read:
			for line in fh_read:
				hex_vendor = PROG_MACVENDOR_STRIPPED.findall(line)

				if len(hex_vendor) > 0:
					# logger.debug(hex_vendor)
					MAC_VENDOR[hex_vendor[0][0]] = hex_vendor[0][1]
		# logger.debug("got %d vendor entries", len(MAC_VENDOR))
	except Exception as ex:
		logger.warning("could not load stripped oui file %r", ex)


def get_vendor_for_mac(mac):
	"""
	mac -- First three bytes of mac address at minimum eg "AA:BB:CC...", "AABBCC..." or
		byte representation b"\xaa\xbb\xcc\xdd\xee\xff"
	return -- found vendor string or empty string
	"""
	if len(MAC_VENDOR) == 1:
		return ""

	if len(MAC_VENDOR) == 0:
		_load_mac_vendor()
		# Avoid loading next time
		if len(MAC_VENDOR) == 0:
			MAC_VENDOR["test"] = "test"

	if type(mac) == bytes:
		# b"\xaa\xbb\xcc\xdd\xee\xff" -> AA:BB:CC:DD:EE:FF -> AABBCC"
		mac = pypacker.mac_bytes_to_str(mac)[0:8].replace(":", "")
	else:
		# AA:BB:CC -> AABBCC
		mac = str.upper(mac.replace(":", "")[0:6])

	#logger.debug("searching mac %s", mac)
	return MAC_VENDOR.get(mac, "")


def is_special_mac(mac_str):
	"""
	Check if this is a special MAC adress (not a client address). Every MAC not found
	in the official OUI database is assumed to be non-client.

	mac_str -- Uppercase mac string like "AA:BB:CC[:DD:EE:FF]", first 3 MAC-bytes are enough
	"""
	return len(get_vendor_for_mac(mac_str)) == 0


def calculate_entropy(elements, granularity_bytes=0, blocksize_bytes=64, log_base=2): # pylint: disable=too-many-locals
	"""
	Calcualte entropy of elements

	elements -- List of elements (each of same length) or a string
	granularity_bytes -- Amount of bytes from which entropy has to be calculated if > 0
		(Entropy per "column", 2nd dimension)
	blocksize_bytes -- If elements is a string: size of the block which is splittet in granularity_bytes
		long strings to calculate the entropy
	return -- Entropy, Entropies (granularity_bytes > 0) or None on error
	"""
	if len(elements) == 0:
		return None

	if type(elements) != list:
		# Only strings allowed
		if type(elements) not in [str, bytes] or granularity_bytes > blocksize_bytes:
			return None
		# Get entropy of a string using a blocksize of blocksize_bytes and granularity of granularity_bytes
		# Example with blocksize_bytes=4, granularity_bytes=1:
		# "12345678" -> "1234", "5678" -> E("1", "2", "3", "4"), E("5", "6", "7", "8")
		# Change default parameter
		if granularity_bytes == 0:
			granularity_bytes = 1
		entropies = []

		for off1 in range(0, len(elements), blocksize_bytes):
			block = elements[off1: off1 + blocksize_bytes]
			#logger.debug(block)
			tokens = [block[off2: off2 + granularity_bytes] for off2 in range(0, len(block), granularity_bytes)]
			#logger.debug(tokens)
			entropy_block = calculate_entropy(tokens)
			#logger.debug(entropy_block)
			entropies.append(entropy_block)
			#time.sleep(60)
		return entropies

	if granularity_bytes != 0:
		# Get Entropy of subsets of bytes of elements: ["1234", "5678"] -> [E("1", "5", ...), ...]
		element_len = len(elements[0])
		entropies = []

		for off in range(0, element_len, granularity_bytes):
			elements_part = []

			for element in elements:
				elements_part.append(element[off: off + granularity_bytes])
			entropy_part = calculate_entropy(elements_part)
			entropies.append(entropy_part)
		return entropies

	symbol_count = collections.defaultdict(lambda: 0)

	for element in elements:
		# Faster than using exceptions
		symbol_count[element] += 1

	#logger.debug(symbol_count)
	entropy = 0
	symbols_total = sum(val for _, val in symbol_count.items())

	for _, count in symbol_count.items():
		p = count / symbols_total
		entropy += log(p, log_base) * p

	return abs(entropy)


def get_mac_for_iface(iface_name):
	"""
	return -- MAC address of the interface iface_name
	Assume MAC address is always retrievable
	"""
	try:
		return netifaces.ifaddresses(iface_name)[netifaces.AF_LINK][0]["addr"]
	except:
		return None


PROG_MAC_AP = re.compile(br"Access Point: (.+)")


def get_mac_of_connected_ap(wifi_interface):
	"""
	return -- MAC address of connected AP on wifi interface, otherweise None
	"""
	try:
		cmd_call = ["iwconfig", wifi_interface]
		output = subprocess.check_output(cmd_call)
		return PROG_MAC_AP.findall(output)[0].strip()
	except:
		return None


def get_ip_addressinfo(iface_name, version=4):
	"""
	iface_name -- Name of the interface to get the information from
	version -- 4 for IPv4, 6 for IPv6
	return -- Adressinfo (ip_address, ip_mask|None, ip_broadcast|None) for the given interface name
		like ("1.2.3.4", "255.255.255.0", "192.168.0.255")
	"""
	version_id = netifaces.AF_INET if version == 4 else netifaces.AF_INET6
	addr_netmask_broadcast = []

	try:
		for addressinfo in netifaces.ifaddresses(iface_name)[version_id]:
			# Honor no broadcast for IPv6
			addr_netmask_broadcast.append(
				(addressinfo.get("addr", None),
				addressinfo.get("netmask", None),
				addressinfo.get("broadcast", None))
			)
	except Exception as ex:
		logger.exception(ex)

	return addr_netmask_broadcast


def nwmask_to_cidr(nmask):
	"""
	nmask -- An IPv4 network mask like "255.255.255.0"
	return -- The amount of network bits in CIDR format like 24
	"""
	return ipaddress.IPv4Network("1.2.3.4/%s" % nmask, strict=False).prefixlen


def get_gwip_for_iface(iface_name, version=4):
	"""
	iface_name -- Name of the interface to get the information from
	version -- 4 for IPv4, 6 for IPv6
	return -- IP address of the default gateway like "1.2.3.4" for interface iface_name or None
	"""
	version_id = netifaces.AF_INET if version == 4 else netifaces.AF_INET6
	gws_ip = netifaces.gateways().get(version_id, None)

	if gws_ip is None:
		return None
	gw_result = None

	for gw_info in gws_ip:
		if iface_name in gw_info:
			gw_result = gw_info[0]
			break
	return gw_result


def get_arp_cache_entry(ipaddr, version=4):
	"""
	return -- MAC address for IP addess like "1.2.3.4"
	"""
	mac = None

	if version == 4:
		pattern_mac = re.compile("([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})")

		with open("/proc/net/arp", "r", encoding="utf-8") as fd:
			for line in fd:
				if line.startswith(ipaddr + " "):
					mac = pattern_mac.search(line).group(0)
					break
	else:
		cmd_call = "ip -6 neigh".split(" ")
		lines = subprocess.check_output(cmd_call).decode("UTF-8").split("\n")
		prefix = "lladdr "
		pattern_mac = re.compile(prefix + "([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})")

		for line in lines:
			if line.startswith(ipaddr + " "):
				mac = pattern_mac.search(line).group(0)
				break
	return mac


def add_arp_entry(ip_address, mac_address, interface_name):
	"""
	Add an arp entry using linux "arp" command.
	"""
	cmd_call = ["arp", "-s", ip_address, "-i", interface_name, mac_address]
	subprocess.check_call(cmd_call)


def flush_arp_cache():
	"""
	Remove all arp entries from cache using linux "ip" command.
	"""
	cmd_call = ["ip", "-s", "neigh", "flush", "all"]
	subprocess.check_call(cmd_call)
