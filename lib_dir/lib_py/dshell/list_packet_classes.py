# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
import pkgutil
import importlib

from pypacker.pypacker import Packet
module_pypacker = importlib.import_module("pypacker")

for importer, modname, ispkg in pkgutil.walk_packages(path=module_pypacker.__path__,
	prefix=module_pypacker.__name__ + ".",
	onerror=lambda x: None):

	if ispkg:
		#print(">>> Found package: %s" % modname)
		pass
	else:
		mod = importlib.import_module(modname)

print("# All pypacker packet classes, their header names and default values ")

packet_subclasses = Packet.__subclasses__()
name_fullclass = {clz.__module__ + "." + clz.__name__: clz for clz in packet_subclasses}
name_fullclass = [(key, value) for key, value in sorted(name_fullclass.items())]

for name, clz in name_fullclass:
	#print(">> %s" % name)
	obj = clz()
	print("%s" % obj)
	print()
