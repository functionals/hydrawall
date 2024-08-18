# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Internetwork Packet Exchange (proprietary protocol)

https://www.novell.com/documentation/nw6p/?page=/documentation/nw6p/ipx_enu/data/hc1w6pvi.html
https://de.wikipedia.org/wiki/Internetwork_Packet_Exchange
"""

from pypacker import pypacker

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
