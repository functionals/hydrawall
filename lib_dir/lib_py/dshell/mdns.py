# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""MDNS"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.layer567 import dns

logger = logging.getLogger("pypacker")

FLAG_NON_AUTH_ACCEPTABLE	= 0x0010

QUERY_TYPE_PTR	= 0x000C
QUERY_CLASS_IN	= 0x0001


def get_bts_for_msg_compression(tl_packet):
	# DNS.Triggestlist[sub] -> sub._triggelistpacket_parent == DNS
	if tl_packet._triggelistpacket_parent is not None:
		return tl_packet._triggelistpacket_parent.header_bytes
	return b""


class MDNS(pypacker.Packet):
	__hdr__ = (
		("tid", "H", 0),
		("flags", "H", 0),
		("q_cnt", "H", 0),
		("ans_cnt", "H", 0),
		("aut_cnt", "H", 0),
		("add_cnt", "H", 0),
		("queries", None, triggerlist.TriggerList)
	)

	class Query(pypacker.Packet):
		__hdr__ = (
			("name", None, b""),
			("type", "H", QUERY_TYPE_PTR),
			("class", "H", QUERY_CLASS_IN)
		)

		name_s = pypacker.get_property_dnsname("name", get_bts_for_msg_compression)

		def compress(self, ref_bts):
			name_compressed = pypacker.compress_dns(self.name, ref_bts)

			if name_compressed is not None:
				#logger.debug("Compressable, assigning %r" % name_compressed)
				self.name = name_compressed

		def _dissect(self, buf):
			namelen = dns.DNS.get_dns_length(buf)
			#logger.debug("Name is: %s" % buf[:off + 1].tobytes())
			self.name = buf[:namelen]
			return namelen + 4

	def _dissect(self, buf):
		self.queries(buf[12:], MDNS._parse_queries)
		return len(buf)

	@staticmethod
	def _parse_queries(buf):
		off = 0
		queries = []

		while off < len(buf):
			# TODO: find name length outside? But then code is doubled (also in query->dissect)
			query = MDNS.Query(buf[off:])
			query.body_bytes = b""
			queries.append(query)

			off += len(query)
		return queries

	def _update_fields(self):
		# Handle compression
		if self.queries._cached_bin is None:
			#logger.debug("_update_fields: no cache, will compress")
			# Something has changed in tl (element or in packet in tl) -> re-compress
			# Start at 2nd element, avoids self-referencing of 1st to itself
			ref_bts = self.header_bytes[:12]

			for idx, val in enumerate(self.queries):
				if type(val) == MDNS.Query:
					val.compress(ref_bts)

				entry_bts = self.queries.entry_to_bytes(idx)
				ref_bts = ref_bts + entry_bts
