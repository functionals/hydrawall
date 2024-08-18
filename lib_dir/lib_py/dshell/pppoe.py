# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""PPP-over-Ethernet."""
from pypacker import pypacker

# RFC 2516 codes
PPPOE_PADI	= 0x09
PPPOE_PADO	= 0x07
PPPOE_PADR	= 0x19
PPPOE_PADS	= 0x65
PPPOE_PADT	= 0xA7
PPPOE_SESSION	= 0x00


class PPPoE(pypacker.Packet):
	__hdr__ = (
		("v_type", "B", 0x11),
		("code", "B", 0),
		("session", "H", 0),
		("len", "H", 0)  # payload length
	)

	def __get_v(self):
		return self.v_type >> 4

	def __set_v(self, v):
		self.v_type = (v << 4) | (self.v_type & 0xF)
	v = property(__get_v, __set_v)

	def __get_type(self):
		return self.v_type & 0xF

	def __set_type(self, t):
		self.v_type = (self.v_type & 0xF0) | t
	type = property(__get_type, __set_type)

	def _dissect(self, buf):
		code = buf[1]
		if code == PPPOE_SESSION:
			return 6, code

		return 6
