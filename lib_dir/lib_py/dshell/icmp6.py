# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Internet Control Message Protocol for IPv6.
https://tools.ietf.org/html/rfc2463
"""
import logging
import struct

from pypacker import pypacker
from pypacker.pypacker import FIELD_FLAG_IS_TYPEFIELD, FIELD_FLAG_AUTOUPDATE
from pypacker import triggerlist
from pypacker import checksum

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
