#Hydrawall

This project is a cyber security suite implementing network forensics, machine learning, and natural language processing.

The artificial intelligence uses an expert system and natural language processing.

Components of this project include:

Dshell, developed by the United States Army Research Lab and dependencies,
 tensorflow machine learning developed by Google, 
 and SWI-Prolog scripts developed by Ian Malloy under funding from the NASA Space Grant Consortium.





# build

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/pypa/build/main.svg)](https://results.pre-commit.ci/latest/github/pypa/build/main)
[![CI test](https://github.com/pypa/build/actions/workflows/test.yml/badge.svg)](https://github.com/pypa/build/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/pypa/build/branch/main/graph/badge.svg)](https://codecov.io/gh/pypa/build)

[![Documentation Status](https://readthedocs.org/projects/pypa-build/badge/?version=latest)](https://build.pypa.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/build.svg)](https://pypi.org/project/build/)
[![Discord](https://img.shields.io/discord/803025117553754132?label=Discord%20chat%20%23build)](https://discord.gg/pypa)

A simple, correct Python build frontend.

See the [documentation](https://build.pypa.io) for more information.

### Installation

`build` can be installed via `pip` or an equivalent via:

```console
$ pip install build
```

### Usage

```console
$ python -m build
```

This will build the package in an isolated environment, generating a
source-distribution and wheel in the directory `dist/`.
See the [documentation](https://build.pypa.io) for full information.

### Code of Conduct

Everyone interacting in the build's codebase, issue trackers, chat rooms, and mailing lists is expected to follow
the [PSF Code of Conduct].

[psf code of conduct]: https://github.com/pypa/.github/blob/main/CODE_OF_CONDUCT.md


# Dshell
An extensible network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.

Key features:
* Deep packet analysis using specialized plugins
* Robust stream reassembly
* IPv4 and IPv6 support
* Multiple user-selectable output formats and the ability to create custom output handlers
* Chainable plugins
* Parallel processing option to divide the handling of data source into separate Python processes
* Enables development of external plugin packs to share and install new externally developed plugins without overlapping the core Dshell plugin directories

## Guides
* [Dshell User Guide](Dshell_User_Guide.pdf) 
  * A guide to installation as well as both basic and advanced analysis with examples
  * Helps new and experienced end users with using and understanding the decoder-shell (Dshell) framework
* [Dshell Developer Guide](Dshell_Developer_Guide.pdf) 
  * A guide to plugin development with basic examples, as well as core function and class definitions, and an overview of data flow
  * Helps end users develop new, custom Dshell plugins as well as modify existing plugins
  
## Requirements
* Linux (developed on Ubuntu 20.04 LTS)
* Python 3 (developed with Python 3.8.10)
* [pypacker](https://gitlab.com/mike01/pypacker)
* [pcapy-ng](https://github.com/stamparm/pcapy-ng/)
* [pyOpenSSL](https://github.com/pyca/pyopenssl)
* [geoip2](https://github.com/maxmind/GeoIP2-python)
  * [MaxMind GeoIP2 data sets](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
    * Used to map IP addresses to country codes
    * See Installation section for configuration 

## Optional
* [oui.txt](http://standards-oui.ieee.org/oui.txt)
  * used by some plugins that handle MAC addresses
  * place in &lt;dshell&gt;/data/
* [elasticsearch](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html)
  * used in the elasticout output module
  * only necessary if planning to use elasticsearch to store output
* [pyJA3](https://github.com/salesforce/ja3/tree/master/python)
  * used in the tls plugin

## Installation

1. Install Dshell with pip
  * `python3 -m pip install Dshell/` OR `python3 -m pip install <Dshell-tarball>`
2. Configure geoip2 by placing the MaxMind GeoLite2 data set files (GeoLite2-ASN.mmdb, GeoLite2-City.mmdb, GeoLite2-Country.mmdb) in [...]/site-packages/dshell/data/GeoIP/
3. Run `dshell`. This should drop you into a `Dshell> ` prompt.

## Basic Usage

* `decode -l`
  * This will list all available plugins, alongside basic information about them
* `decode -h`
  * Show generic command-line flags available to most plugins, such as the color blind friendly mode for all color output
* `decode -p <plugin>`
  * Display information about a plugin, including available command line flags
* `decode -p <plugin> <pcap>`
  * Run the selected plugin on a pcap or pcapng file
* `decode -p <plugin1>+<plugin2> <pcap>`
  * Chain two (or more) plugins together and run them on a pcap file
* `decode -p <plugin> -i <interface>`
  * Run the selected plugin live on an interface (may require superuser privileges)

## Usage Examples
Showing DNS lookups in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -p dns ~/pcap/dns.cap | sort
[DNS] 2005-03-30 03:47:46    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 4146, TXT? google.com., TXT: b'\x0fv=spf1 ptr ?all' **
[DNS] 2005-03-30 03:47:50    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 63343, MX? google.com., MX: b'\x00(\x05smtp4\xc0\x0c', MX: b'\x00\n\x05smtp5\xc0\x0c', MX: b'\x00\n\x05smtp6\xc0\x0c', MX: b'\x00\n\x05smtp1\xc0\x0c', MX: b'\x00\n\x05smtp2\xc0\x0c', MX: b'\x00(\x05smtp3\xc0\x0c' **
[DNS] 2005-03-30 03:47:59    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 18849, LOC? google.com. **
[DNS] 2005-03-30 03:48:07    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 39867, PTR? 104.9.192.66.in-addr.arpa., PTR: 66-192-9-104.gen.twtelecom.net. **
[DNS] 2005-03-30 03:49:18    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 30144, A? www.netbsd.org., A: 204.152.190.12 (ttl 82159s) **
[DNS] 2005-03-30 03:49:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 61652, AAAA? www.netbsd.org., AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86400s) **
[DNS] 2005-03-30 03:50:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 32569, AAAA? www.netbsd.org., AAAA: 2001:4f8:4:7:2e0:81ff:fe52:9a6b (ttl 86340s) **
[DNS] 2005-03-30 03:50:44    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 36275, AAAA? www.google.com., CNAME: 'www.l.google.com.' **
[DNS] 2005-03-30 03:50:54    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 56482, AAAA? www.l.google.com. **
[DNS] 2005-03-30 03:51:35    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 48159, AAAA? www.example.com. **
[DNS] 2005-03-30 03:51:46    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 9837, AAAA? www.example.notginh., NXDOMAIN **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32795 --   192.168.170.20:53    ** ID: 65251, AAAA: 2001:4f8:0:2::d (ttl 600s), A: 204.152.184.88 (ttl 600s) **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32796 --   192.168.170.20:53    ** ID: 23123, PTR? 1.0.0.127.in-addr.arpa., PTR: localhost. **
[DNS] 2005-03-30 03:52:17    192.168.170.8:32797 --   192.168.170.20:53    ** ID: 8330, NS: b'\x06ns-ext\x04nrt1\xc0\x0c', NS: b'\x06ns-ext\x04sth1\xc0\x0c', NS: b'\x06ns-ext\xc0\x0c', NS: b'\x06ns-ext\x04lga1\xc0\x0c' **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1707  --      217.13.4.24:53    ** ID: 12910, SRV? _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1708  --      217.13.4.24:53    ** ID: 61793, SRV? _ldap._tcp.dc._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1709  --      217.13.4.24:53    ** ID: 33633, SRV? _ldap._tcp.05b5292b-34b8-4fb7-85a3-8beef5fd2069.domains._msdcs.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:17   192.168.170.56:1710  --      217.13.4.24:53    ** ID: 53344, A? GRIMM.utelsystems.local., NXDOMAIN **
[DNS] 2005-03-30 03:52:25   192.168.170.56:1711  --      217.13.4.24:53    ** ID: 30307, A? GRIMM.utelsystems.local., NXDOMAIN **
```

Following and reassembling a stream in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted)

```
Dshell> decode -p followstream ~/pcap/v6-http.cap 
Connection 1 (TCP)
Start: 2007-08-05 15:16:44.189851
End:   2007-08-05 15:16:44.219460
2001:6f8:102d:0:2d0:9ff:fee3:e8de: 59201 -> 2001:6f8:900:7c0::2:    80 (300 bytes)
2001:6f8:900:7c0::2:    80 -> 2001:6f8:102d:0:2d0:9ff:fee3:e8de: 59201 (2379 bytes)

GET / HTTP/1.0
Host: cl-1985.ham-01.de.sixxs.net
Accept: text/html, text/plain, text/css, text/sgml, */*;q=0.01
Accept-Encoding: gzip, bzip2
Accept-Language: en
User-Agent: Lynx/2.8.6rel.2 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8b



HTTP/1.1 200 OK
Date: Sun, 05 Aug 2007 19:16:44 GMT
Server: Apache
Content-Length: 2121
Connection: close
Content-Type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /</title>
 </head>
 <body>
<h1>Index of /</h1>
<pre><img src="/icons/blank.gif" alt="Icon "> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr><img src="/icons/folder.gif" alt="[DIR]"> <a href="202-vorbereitung/">202-vorbereitung/</a>       06-Jul-2007 14:31    -   
<img src="/icons/layout.gif" alt="[   ]"> <a href="Efficient_Video_on_demand_over_Multicast.pdf">Efficient_Video_on_d..&gt;</a> 19-Dec-2006 03:17  291K  
<img src="/icons/unknown.gif" alt="[   ]"> <a href="Welcome%20Stranger!!!">Welcome Stranger!!!</a>     28-Dec-2006 03:46    0   
<img src="/icons/text.gif" alt="[TXT]"> <a href="barschel.htm">barschel.htm</a>            31-Jul-2007 02:21   44K  
<img src="/icons/folder.gif" alt="[DIR]"> <a href="bnd/">bnd/</a>                    30-Dec-2006 08:59    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="cia/">cia/</a>                    28-Jun-2007 00:04    -   
<img src="/icons/layout.gif" alt="[   ]"> <a href="cisco_ccna_640-801_command_reference_guide.pdf">cisco_ccna_640-801_c..&gt;</a> 28-Dec-2006 03:48  236K  
<img src="/icons/folder.gif" alt="[DIR]"> <a href="doc/">doc/</a>                    19-Sep-2006 01:43    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="freenetproto/">freenetproto/</a>           06-Dec-2006 09:00    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="korrupt/">korrupt/</a>                03-Jul-2007 11:57    -   
<img src="/icons/folder.gif" alt="[DIR]"> <a href="mp3_technosets/">mp3_technosets/</a>         04-Jul-2007 08:56    -   
<img src="/icons/text.gif" alt="[TXT]"> <a href="neues_von_rainald_goetz.htm">neues_von_rainald_go..&gt;</a> 21-Mar-2007 23:27   31K  
<img src="/icons/text.gif" alt="[TXT]"> <a href="neues_von_rainald_goetz0.htm">neues_von_rainald_go..&gt;</a> 21-Mar-2007 23:29   36K  
<img src="/icons/layout.gif" alt="[   ]"> <a href="pruef.pdf">pruef.pdf</a>               28-Dec-2006 07:48   88K  
<hr></pre>
</body></html>
```

Chaining plugins to view flow data for a specific country code in [sample traffic](http://wiki.wireshark.org/SampleCaptures#General_.2F_Unsorted) (note: TCP handshakes are not included in the packet count)

```
Dshell> decode -p country+netflow --country_code=JP ~/pcap/SkypeIRC.cap
2006-08-25 15:32:20.766761       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33438     1      0       64        0  0.0000s
2006-08-25 15:32:20.634046       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33435     1      0       64        0  0.0000s
2006-08-25 15:32:20.747503       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33437     1      0       64        0  0.0000s
2006-08-25 15:32:20.651501       192.168.1.2 ->  202.232.205.123  (-- -> JP)   UDP   60583   33436     1      0       64        0  0.0000s
```

Collecting DNS traffic from several files and storing it in a new pcap file.

```
Dshell> decode -p dns+pcapwriter --pcapwriter_outfile=test.pcap ~/pcap/*.cap > /dev/null
Dshell> tcpdump -nnr test.pcap | head
reading from file test.pcap, link-type EN10MB (Ethernet)
15:36:08.670569 IP 192.168.1.2.2131 > 192.168.1.1.53: 40209+ A? ui.skype.com. (30)
15:36:08.670687 IP 192.168.1.2.2131 > 192.168.1.1.53: 40210+ AAAA? ui.skype.com. (30)
15:36:08.674022 IP 192.168.1.1.53 > 192.168.1.2.2131: 40209- 1/0/0 A 212.72.49.131 (46)
15:36:09.011208 IP 192.168.1.1.53 > 192.168.1.2.2131: 40210 0/1/0 (94)
15:36:10.171350 IP 192.168.1.2.2131 > 192.168.1.1.53: 40210+ AAAA? ui.skype.com. (30)
15:36:10.961350 IP 192.168.1.1.53 > 192.168.1.2.2131: 40210* 0/1/0 (85)
15:36:10.961608 IP 192.168.1.2.2131 > 192.168.1.1.53: 40211+ AAAA? ui.skype.com. (30)
15:36:11.294333 IP 192.168.1.1.53 > 192.168.1.2.2131: 40211 0/1/0 (94)
15:32:21.664798 IP 192.168.1.2.2130 > 192.168.1.1.53: 39862+ A? ui.skype.com. (30)
15:32:21.664913 IP 192.168.1.2.2130 > 192.168.1.1.53: 39863+ AAAA? ui.skype.com. (30)
```

Collecting TFTP data and converting alerts to JSON format using [sample traffic](https://wiki.wireshark.org/SampleCaptures#TFTP)

```
Dshell> decode -p tftp -O jsonout ~/pcap/tftp_*.pcap
{"ts": 1367411051.972852, "sip": "192.168.0.253", "sport": 50618, "dip": "192.168.0.10", "dport": 3445, "readwrite": "read", "filename": "rfc1350.txt", "plugin": "tftp", "pcapfile": "/home/pcap/tftp_rrq.pcap", "data": "read  rfc1350.txt (24599 bytes) "}
{"ts": 1367053679.45274, "sip": "192.168.0.1", "sport": 57509, "dip": "192.168.0.13", "dport": 2087, "readwrite": "write", "filename": "rfc1350.txt", "plugin": "tftp", "pcapfile": "/home/pcap/tftp_wrq.pcap", "data": "write rfc1350.txt (24599 bytes) "}
```

Running a plugin within a separate Python script using [sample traffic](https://wiki.wireshark.org/SampleCaptures#TFTP)

```
# Import required Dshell libraries
import dshell.decode as decode
import dshell.plugins.tftp.tftp as tftp

# Instantiate plugin
plugin = tftp.DshellPlugin()
# Define plugin-specific arguments, if needed
dargs = {plugin: {"rip": True, "outdir": "/tmp/"}}
# Add plugin(s) to plugin chain
decode.plugin_chain = [plugin]
# Run decode main function with all other arguments
decode.main(
    debug=True,
    files=["/home/user/pcap/tftp_rrq.pcap", "/home/user/pcap/tftp_wrq.pcap"],
    plugin_args=dargs
)
```


=========================
MaxMind GeoIP2 Python API
=========================

Description
-----------

This package provides an API for the GeoIP2 and GeoLite2 `web services
<https://dev.maxmind.com/geoip/docs/web-services?lang=en>`_ and `databases
<https://dev.maxmind.com/geoip/docs/databases?lang=en>`_.

Installation
------------

To install the ``geoip2`` module, type:

.. code-block:: bash

    $ pip install geoip2

If you are not able to use pip, you may also use easy_install from the
source directory:

.. code-block:: bash

    $ easy_install .

Database Reader Extension
^^^^^^^^^^^^^^^^^^^^^^^^^

If you wish to use the C extension for the database reader, you must first
install the `libmaxminddb C API <https://github.com/maxmind/libmaxminddb>`_.
Please `see the instructions distributed with it
<https://github.com/maxmind/libmaxminddb/blob/main/README.md>`_.

IP Geolocation Usage
--------------------

IP geolocation is inherently imprecise. Locations are often near the center of
the population. Any location provided by a GeoIP2 database or web service
should not be used to identify a particular address or household.

Web Service Usage
-----------------

To use this API, you first construct either a ``geoip2.webservice.Client`` or
``geoip2.webservice.AsyncClient``, passing your MaxMind ``account_id`` and
``license_key`` to the constructor. To use the GeoLite2 web service instead of
the GeoIP2 web service, set the optional ``host`` keyword argument to
``geolite.info``. To use the Sandbox GeoIP2 web service instead of the
production GeoIP2 web service, set the optional ``host`` keyword argument to
``sandbox.maxmind.com``.

After doing this, you may call the method corresponding to request type
(e.g., ``city`` or ``country``), passing it the IP address you want to look up.

If the request succeeds, the method call will return a model class for the
endpoint you called. This model in turn contains multiple record classes,
each of which represents part of the data returned by the web service.

If the request fails, the client class throws an exception.

Sync Web Service Example
------------------------

.. code-block:: pycon

    >>> import geoip2.webservice
    >>>
    >>> # This creates a Client object that can be reused across requests.
    >>> # Replace "42" with your account ID and "license_key" with your license
    >>> # key. Set the "host" keyword argument to "geolite.info" to use the
    >>> # GeoLite2 web service instead of the GeoIP2 web service. Set the
    >>> # "host" keyword argument to "sandbox.maxmind.com" to use the Sandbox
    >>> # GeoIP2 web service instead of the production GeoIP2 web service.
    >>> with geoip2.webservice.Client(42, 'license_key') as client:
    >>>
    >>>     # Replace "city" with the method corresponding to the web service
    >>>     # that you are using, i.e., "country", "city", or "insights". Please
    >>>     # note that Insights is not supported by the GeoLite2 web service.
    >>>     response = client.city('203.0.113.0')
    >>>
    >>>     response.country.iso_code
    'US'
    >>>     response.country.name
    'United States'
    >>>     response.country.names['zh-CN']
    u'美国'
    >>>
    >>>     response.subdivisions.most_specific.name
    'Minnesota'
    >>>     response.subdivisions.most_specific.iso_code
    'MN'
    >>>
    >>>     response.city.name
    'Minneapolis'
    >>>
    >>>     response.postal.code
    '55455'
    >>>
    >>>     response.location.latitude
    44.9733
    >>>     response.location.longitude
    -93.2323
    >>>
    >>>     response.traits.network
    IPv4Network('203.0.113.0/32')

Async Web Service Example
-------------------------

.. code-block:: pycon

    >>> import asyncio
    >>>
    >>> import geoip2.webservice
    >>>
    >>> async def main():
    >>>     # This creates an AsyncClient object that can be reused across
    >>>     # requests on the running event loop. If you are using multiple event
    >>>     # loops, you must ensure the object is not used on another loop.
    >>>     #
    >>>     # Replace "42" with your account ID and "license_key" with your license
    >>>     # key. Set the "host" keyword argument to "geolite.info" to use the
    >>>     # GeoLite2 web service instead of the GeoIP2 web service. Set the
    >>>     # "host" keyword argument to "sandbox.maxmind.com" to use the Sandbox
    >>>     # GeoIP2 web service instead of the production GeoIP2 web service.
    >>>     async with geoip2.webservice.AsyncClient(42, 'license_key') as client:
    >>>
    >>>         # Replace "city" with the method corresponding to the web service
    >>>         # that you are using, i.e., "country", "city", or "insights". Please
    >>>         # note that Insights is not supported by the GeoLite2 web service.
    >>>         response = await client.city('203.0.113.0')
    >>>
    >>>         response.country.iso_code
    'US'
    >>>         response.country.name
    'United States'
    >>>         response.country.names['zh-CN']
    u'美国'
    >>>
    >>>         response.subdivisions.most_specific.name
    'Minnesota'
    >>>         response.subdivisions.most_specific.iso_code
    'MN'
    >>>
    >>>         response.city.name
    'Minneapolis'
    >>>
    >>>         response.postal.code
    '55455'
    >>>
    >>>         response.location.latitude
    44.9733
    >>>         response.location.longitude
    -93.2323
    >>>
    >>>         response.traits.network
    IPv4Network('203.0.113.0/32')
    >>>
    >>> asyncio.run(main())

Web Service Client Exceptions
-----------------------------

For details on the possible errors returned by the web service itself, see
https://dev.maxmind.com/geoip/docs/web-services?lang=en for the GeoIP2 web
service docs.

If the web service returns an explicit error document, this is thrown as a
``AddressNotFoundError``, ``AuthenticationError``, ``InvalidRequestError``, or
``OutOfQueriesError`` as appropriate. These all subclass ``GeoIP2Error``.

If some other sort of error occurs, this is thrown as an ``HTTPError``. This
is thrown when some sort of unanticipated error occurs, such as the web
service returning a 500 or an invalid error document. If the web service
returns any status code besides 200, 4xx, or 5xx, this also becomes an
``HTTPError``.

Finally, if the web service returns a 200 but the body is invalid, the client
throws a ``GeoIP2Error``.

Database Usage
--------------

To use the database API, you first construct a ``geoip2.database.Reader`` using
the path to the file as the first argument. After doing this, you may call the
method corresponding to database type (e.g., ``city`` or ``country``), passing it
the IP address you want to look up.

If the lookup succeeds, the method call will return a model class for the
database method you called. This model in turn contains multiple record classes,
each of which represents part of the data for the record.

If the request fails, the reader class throws an exception.

Database Example
----------------

City Database
^^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoLite2-City.mmdb') as reader:
    >>>
    >>>     # Replace "city" with the method corresponding to the database
    >>>     # that you are using, e.g., "country".
    >>>     response = reader.city('203.0.113.0')
    >>>
    >>>     response.country.iso_code
    'US'
    >>>     response.country.name
    'United States'
    >>>     response.country.names['zh-CN']
    u'美国'
    >>>
    >>>     response.subdivisions.most_specific.name
    'Minnesota'
    >>>     response.subdivisions.most_specific.iso_code
    'MN'
    >>>
    >>>     response.city.name
    'Minneapolis'
    >>>
    >>>     response.postal.code
    '55455'
    >>>
    >>>     response.location.latitude
    44.9733
    >>>     response.location.longitude
    -93.2323
    >>>
    >>>     response.traits.network
    IPv4Network('203.0.113.0/24')

Anonymous IP Database
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoIP2-Anonymous-IP.mmdb') as reader:
    >>>
    >>>     response = reader.anonymous_ip('203.0.113.0')
    >>>
    >>>     response.is_anonymous
    True
    >>>     response.is_anonymous_vpn
    False
    >>>     response.is_hosting_provider
    False
    >>>     response.is_public_proxy
    False
    >>>     response.is_residential_proxy
    False
    >>>     response.is_tor_exit_node
    True
    >>>     response.ip_address
    '203.0.113.0'
    >>>     response.network
    IPv4Network('203.0.113.0/24')

ASN Database
^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoLite2-ASN.mmdb') as reader:
    >>>     response = reader.asn('203.0.113.0')
    >>>     response.autonomous_system_number
    1221
    >>>     response.autonomous_system_organization
    'Telstra Pty Ltd'
    >>>     response.ip_address
    '203.0.113.0'
    >>>     response.network
    IPv4Network('203.0.113.0/24')

Connection-Type Database
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoIP2-Connection-Type.mmdb') as reader:
    >>>     response = reader.connection_type('203.0.113.0')
    >>>     response.connection_type
    'Corporate'
    >>>     response.ip_address
    '203.0.113.0'
    >>>     response.network
    IPv4Network('203.0.113.0/24')


Domain Database
^^^^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoIP2-Domain.mmdb') as reader:
    >>>     response = reader.domain('203.0.113.0')
    >>>     response.domain
    'umn.edu'
    >>>     response.ip_address
    '203.0.113.0'

Enterprise Database
^^^^^^^^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoIP2-Enterprise.mmdb') as reader:
    >>>
    >>>     # Use the .enterprise method to do a lookup in the Enterprise database
    >>>     response = reader.enterprise('203.0.113.0')
    >>>
    >>>     response.country.confidence
    99
    >>>     response.country.iso_code
    'US'
    >>>     response.country.name
    'United States'
    >>>     response.country.names['zh-CN']
    u'美国'
    >>>
    >>>     response.subdivisions.most_specific.name
    'Minnesota'
    >>>     response.subdivisions.most_specific.iso_code
    'MN'
    >>>     response.subdivisions.most_specific.confidence
    77
    >>>
    >>>     response.city.name
    'Minneapolis'
    >>>     response.country.confidence
    11
    >>>
    >>>     response.postal.code
    '55455'
    >>>
    >>>     response.location.accuracy_radius
    50
    >>>     response.location.latitude
    44.9733
    >>>     response.location.longitude
    -93.2323
    >>>
    >>>     response.traits.network
    IPv4Network('203.0.113.0/24')


ISP Database
^^^^^^^^^^^^

.. code-block:: pycon

    >>> import geoip2.database
    >>>
    >>> # This creates a Reader object. You should use the same object
    >>> # across multiple requests as creation of it is expensive.
    >>> with geoip2.database.Reader('/path/to/GeoIP2-ISP.mmdb') as reader:
    >>>     response = reader.isp('203.0.113.0')
    >>>     response.autonomous_system_number
    1221
    >>>     response.autonomous_system_organization
    'Telstra Pty Ltd'
    >>>     response.isp
    'Telstra Internet'
    >>>     response.organization
    'Telstra Internet'
    >>>     response.ip_address
    '203.0.113.0'
    >>>     response.network
    IPv4Network('203.0.113.0/24')

Database Reader Exceptions
--------------------------

If the database file does not exist or is not readable, the constructor will
raise a ``FileNotFoundError`` or a ``PermissionError``. If the IP address passed
to a method is invalid, a ``ValueError`` will be raised. If the file is invalid
or there is a bug in the reader, a ``maxminddb.InvalidDatabaseError`` will be
raised with a description of the problem. If an IP address is not in the
database, a ``AddressNotFoundError`` will be raised.

``AddressNotFoundError`` references the largest subnet where no address would be
found. This can be used to efficiently enumerate entire subnets:

.. code-block:: python

    import geoip2.database
    import geoip2.errors
    import ipaddress

    # This creates a Reader object. You should use the same object
    # across multiple requests as creation of it is expensive.
    with geoip2.database.Reader('/path/to/GeoLite2-ASN.mmdb') as reader:
        network = ipaddress.ip_network("192.128.0.0/15")

        ip_address = network[0]
        while ip_address in network:
            try:
                response = reader.asn(ip_address)
                response_network = response.network
            except geoip2.errors.AddressNotFoundError as e:
                response = None
                response_network = e.network
            print(f"{response_network}: {response!r}")
            ip_address = response_network[-1] + 1  # move to next subnet

Values to use for Database or Dictionary Keys
---------------------------------------------

**We strongly discourage you from using a value from any ``names`` property as
a key in a database or dictionaries.**

These names may change between releases. Instead we recommend using one of the
following:

* ``geoip2.records.City`` - ``city.geoname_id``
* ``geoip2.records.Continent`` - ``continent.code`` or ``continent.geoname_id``
* ``geoip2.records.Country`` and ``geoip2.records.RepresentedCountry`` - ``country.iso_code`` or ``country.geoname_id``
* ``geoip2.records.subdivision`` - ``subdivision.iso_code`` or ``subdivision.geoname_id``

What data is returned?
----------------------

While many of the models contain the same basic records, the attributes which
can be populated vary between web service endpoints or databases. In
addition, while a model may offer a particular piece of data, MaxMind does not
always have every piece of data for any given IP address.

Because of these factors, it is possible for any request to return a record
where some or all of the attributes are unpopulated.

The only piece of data which is always returned is the ``ip_address``
attribute in the ``geoip2.records.Traits`` record.

Integration with GeoNames
-------------------------

`GeoNames <https://www.geonames.org/>`_ offers web services and downloadable
databases with data on geographical features around the world, including
populated places. They offer both free and paid premium data. Each feature is
uniquely identified by a ``geoname_id``, which is an integer.

Many of the records returned by the GeoIP web services and databases include a
``geoname_id`` field. This is the ID of a geographical feature (city, region,
country, etc.) in the GeoNames database.

Some of the data that MaxMind provides is also sourced from GeoNames. We
source things like place names, ISO codes, and other similar data from the
GeoNames premium data set.

Reporting Data Problems
-----------------------

If the problem you find is that an IP address is incorrectly mapped, please
`submit your correction to MaxMind <https://www.maxmind.com/en/correction>`_.

If you find some other sort of mistake, like an incorrect spelling, please
check the `GeoNames site <https://www.geonames.org/>`_ first. Once you've
searched for a place and found it on the GeoNames map view, there are a
number of links you can use to correct data ("move", "edit", "alternate
names", etc.). Once the correction is part of the GeoNames data set, it
will be automatically incorporated into future MaxMind releases.

If you are a paying MaxMind customer and you're not sure where to submit a
correction, please `contact MaxMind support
<https://www.maxmind.com/en/support>`_ for help.

Requirements
------------

Python 3.8 or greater is required. Older versions are not supported.

The Requests HTTP library is also required. See
<https://pypi.org/project/requests/> for details.

Versioning
----------

The GeoIP2 Python API uses `Semantic Versioning <https://semver.org/>`_.

Support
-------

Please report all issues with this code using the `GitHub issue tracker
<https://github.com/maxmind/GeoIP2-python/issues>`_

If you are having an issue with a MaxMind service that is not specific to the
client API, please contact `MaxMind support
<https://www.maxmind.com/en/support>`_ for assistance.



# JA3 - A method for profiling SSL/TLS Clients

JA3 was invented at Salesforce in 2017. However, the project is no longer being actively maintained by Salesforce. Its original creator, John Althouse, maintains the latest in TLS client fingerprinting technology at [FoxIO-LLC](https://github.com/FoxIO-LLC/ja4).

JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

Before using, please read this blog post: [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

This repo includes JA3 and JA3S scripts for [Zeek](https://www.zeekurity.org/) and [Python](https://www.python.org/). You can find a nice Rust implementation of the JA3 algorithm [here](https://github.com/jabedude/ja3-rs)

JA3 support has also been added to:  
[Moloch](http://molo.ch/)  
[Trisul NSM](https://github.com/trisulnsm/trisul-scripts/tree/master/lua/frontend_scripts/reassembly/ja3)  
[NGiNX](https://github.com/fooinha/nginx-ssl-ja3)
[BFE](https://github.com/bfenetworks/bfe)
[MISP](https://github.com/MISP)  
[Darktrace](https://www.darktrace.com/)  
[Suricata](https://suricata-ids.org/tag/ja3/)  
[Elastic.co Packetbeat](https://www.elastic.co/guide/en/beats/packetbeat/master/exported-fields-tls.html)  
[Splunk](https://www.splunk.com/blog/2017/12/18/configuring-ja3-with-bro-for-splunk.html)  
[MantisNet](https://www.mantisnet.com/)  
[ICEBRG](http://icebrg.io/)  
[Redsocks](https://www.redsocks.eu/)  
[NetWitness](https://github.com/timetology/nw/tree/master/parsers/ssl_ja3)  
[ExtraHop](https://www.extrahop.com/)  
[Vectra Cognito Platform](https://vectra.ai/)  
[Corvil](https://www.corvil.com/blog/2018/environmentally-conscious-understanding-your-network)  
[Java](https://github.com/lafaspot/ja3_4java)  
[Go](https://github.com/open-ch/ja3)  
[Security Onion](https://securityonion.net/)   
[AIEngine](https://bitbucket.org/camp0/aiengine)  
[RockNSM](https://rocknsm.io/)  
[Corelight](https://www.corelight.com/products/software)  
[VirusTotal](https://blog.virustotal.com/2019/10/in-house-dynamic-analysis-virustotal-jujubox.html#ja3)  
[SELKS](https://www.stamus-networks.com/selks-6)  
[Stamus Networks](https://www.stamus-networks.com/)  
[IBM QRadar Network Insights (QNI)](https://community.ibm.com/community/user/security/blogs/tom-obremski1/2020/10/23/qni-ja3-ja3s-for-network-encryption)  
[InQuest](https://inquest.net)  
[Cloudflare](https://developers.cloudflare.com/bots/concepts/ja3-fingerprint/)  
[AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-threat-signature.html)  
[Azure Firewall](https://learn.microsoft.com/en-us/azure/firewall/idps-signature-categories)  
[AWS WAF](https://aws.amazon.com/about-aws/whats-new/2023/09/aws-waf-ja3-fingerprint-match/)  
[Google Cloud](https://cloud.google.com/load-balancing/docs/https/custom-headers-global)  
and more...  


## Examples

JA3 fingerprint for the standard Tor client:  
```
e7d705a3286e19ea42f587b344ee6865
```
JA3 fingerprint for the Trickbot malware:
```
6734f37431670b3ab4292b8f60f29984
```
JA3 fingerprint for the Emotet malware:
```
4d7a28d6f2263ed61de88ca66eb011e3
```

While destination IPs, Ports, and X509 certificates change, the JA3 fingerprint remains constant for the client application in these examples across our sample set. Please be aware that these are just examples, not indicative of all versions ever.

## Lists

Example lists of known JA3's and their associated applications can be found [here](https://github.com/salesforce/ja3/tree/master/lists).  

A more up-to-date crowd sourced method of gathering and reporting on JA3s can be found at [ja3er.com](https://ja3er.com).  

## How it works

TLS and it’s predecessor, SSL, I will refer to both as “SSL” for simplicity, are used to encrypt communication for both common applications, to keep your data secure, and malware, so it can hide in the noise. To initiate a SSL session, a client will send a SSL Client Hello packet following the TCP 3-way handshake. This packet and the way in which it is generated is dependant on packages and methods used when building the client application. The server, if accepting SSL connections, will respond with a SSL Server Hello packet that is formulated based on server-side libraries and configurations as well as details in the Client Hello. Because SSL negotiations are transmitted in the clear, it’s possible to fingerprint and identify client applications using the details in the SSL Client Hello packet.

JA3 is a method of TLS fingerprinting that was inspired by the [research](https://blog.squarelemon.com/tls-fingerprinting/) and works of [Lee Brotherston](https://twitter.com/synackpse) and his TLS Fingerprinting tool: [FingerprinTLS](https://github.com/LeeBrotherston/tls-fingerprinting/tree/master/fingerprintls). 

JA3 gathers the decimal values of the bytes for the following fields in the Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. It then concatenates those values together in order, using a "," to delimit each field and a "-" to delimit each value in each field.

The field order is as follows:
```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```
Example:
```    
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
```
If there are no SSL Extensions in the Client Hello, the fields are left empty. 

Example:
```   
769,4-5-10-9-100-98-3-6-19-18-99,,,
```
These strings are then MD5 hashed to produce an easily consumable and shareable 32 character fingerprint. This is the JA3 SSL Client Fingerprint.
```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
```
We also needed to introduce some code to account for Google’s GREASE (Generate Random Extensions And Sustain Extensibility) as described [here](https://tools.ietf.org/html/draft-davidben-tls-grease-01). Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem.  JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.

## JA3S

JA3S is JA3 for the Server side of the SSL/TLS communication and fingerprints how servers respond to particular clients. 

JA3S uses the following field order:
```
SSLVersion,Cipher,SSLExtension
```
With JA3S it is possible to fingerprint the entire cryptographic negotiation between client and it's server by combining JA3 + JA3S. That is because servers will respond to different clients differently but will always respond to the same client the same.

For the Trickbot example:
```
JA3 = 6734f37431670b3ab4292b8f60f29984 ( Fingerprint of Trickbot )
JA3S = 623de93db17d313345d7ea481e7443cf ( Fingerprint of Command and Control Server Response )
```
For the Emotet example:
```
JA3 = 4d7a28d6f2263ed61de88ca66eb011e3 ( Fingerprint of Emotet )
JA3S = 80b3a14bccc8598a1f3bbe83e71f735f ( Fingerprint of Command and Control Server Response )
```

In these malware examples, the command and control server always responds to the malware client in exactly the same way, it does not deviate. So even though the traffic is encrypted and one may not know the command and control server's IPs or domains as they are constantly changing, we can still identify, with reasonable confidence, the malicious communication by fingerprinting the TLS negotiation between client and server. Again, please be aware that these are examples, not indicative of all versions ever, and are intended to illustrate what is possible.

## Intriguing Possibilities

JA3 is a much more effective way to detect malicious activity over SSL than IP or domain based IOCs. Since JA3 detects the client application, it doesn’t matter if malware uses DGA (Domain Generation Algorithms), or different IPs for each C2 host, or even if the malware uses Twitter for C2, JA3 can detect the malware itself based on how it communicates rather than what it communicates to.

JA3 is also an excellent detection mechanism in locked-down environments where only a few specific applications are allowed to be installed. In these types of environments one could build a whitelist of expected applications and then alert on any other JA3 hits.

For more details on what you can see and do with JA3 and JA3S, please see this DerbyCon 2018 talk: https://www.youtube.com/watch?v=NI0Lmp0K1zc or this [blog post.](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)

Please contact me on twitter @4A4133 or over email, let me know what you find and if you have any feature requests. 

___  
### JA3 Created by

[John Althouse](https://www.linkedin.com/in/johnalthouse/)  
[Jeff Atkinson](https://www.linkedin.com/in/annh/)  
[Josh Atkins](https://www.linkedin.com/in/joshratkins/)  

Please send questions and comments to **[John Althouse](https://twitter.com/4A4133)**.



# Janus-swi: a bi-directional interface between SWI-Prolog and Python

This  code  implements  a  ready-to-use  bi-directional  interface  to
Python.  As  motivated by Theresa  Swift, Python opens many  doors for
accessing resources such as graphics, machine learning and many more.

The  API defined  in this  interface has  been established  as a  PIP,
_Prolog Improvement Proposal_.  When the PIP is finished and published
we  will  properly  reference  it.  The  main  predicates  and  Python
functions of this interface are compatible with the XSB Python package
`janus_xsb`.   Both `janus_swi`  and `janus_xsb`  implement extensions
upon  the   agreed  interface.   For  example,   `janus_swi`  supports
SWI-Prolog dicts and defines thread synchronization between Prolog and
Python.

## Documentation

See [SWI-Prolog manual](https://www.swi-prolog.org/pldoc/package/janus)

## Bi-directional

This  GIT repository  is a  GIT _submodule_  of the  SWI-Prolog source
repository.  As part of the  SWI-Prolog source distribution it is used
to build `library(janus)`, a Prolog  library that embeds Python.  This
same  module can  be  used  stand-alone to  build  the Python  package
`janus_swi` that embeds Prolog into  Python.  Loaded either way, Janus
is the same and allows for mutually recursive calls between Prolog and
Python.


## Embedding Prolog into Python: the Python janus_swi package

If  this  repository   is  used  to  build  the   Python  pip  package
`janus_swi`, we can  load SWI-Prolog into Python  and call predicates.
For example:

    python
	>>> import janus_swi as janus
	>>> janus.query_once("writeln('Hello world!')")
	Hello world!
	{'truth': True}
	>>>

The    Python    package    is     available    from    __PyPi__    as
[janus-swi](https://pypi.org/project/janus-swi/).      We    currently
provide  a few  _wheels_ for  Windows.   The binaries  in the  Windows
_wheel_ probably supports all Python and Prolog versions that are also
supported by  the source.   The package can  be installed  using `pip`
from source on any system with CPython 3.6 or later, SWI-Prolog 9.1.12
or later and a  C compiler.  For compiling the C  code, GCC, Clang and
VS2022 have been tested.  Thus,  normally the package can be installed
using

    pip install janus-swi

SWI-Prolog is  selected by  finding `swipl`  on the  executable search
path.   If `swipl.exe`  is not  in ``%PATH%``  on Windows  the Windows
registry is examined to find SWI-Prolog.

If  you installed  SWI-Prolog from  source, it  is advices  to install
Janus from the  `packages/swipy` directory in the  Prolog source.  The
package can be installed from within this directory using

    pip install .


## Embedding Python into Prolog: library(janus)

Configuration and installation of `library(janus)` which embeds Python
into Prolog is  handled by the normal  Prolog configuration.  Building
the  interface  requires  the  libraries  and  C  headers  for  Python
embedding to be installed.   Below are the commands for installing the
embedded Python engine for Ubuntu and Fedora Linux.

    apt install python3 libpython3-dev   # Ubuntu
    dnf install python3-devel            # Fedora

If  you need  to  build  Python, the  following  command is  suggested
(assuming you wish to install  it in `$HOME/.local/bin`). You may also
need the option `--enable-shared`.

    CFLAGS='-fPIC' CCSHARED='-fPIC' ./configure --prefix=$HOME/.local --enable-optimizations
    make -j8   # change "8" to the number of CPUs on your machine
    make install

On __MacOS__,  these files are  included in the Homebrew  and Macports
versions of Python

On  Windows,  these  files  are included  in  the  default  installer.
Configuration requires Python to appear in ``%PATH%``.

After successful installation, running `py_version/0` should result in
printing relevant information on the embedded Python system.

    ?- py_version.
	% Janus embeds Python 3.10.12 (main, Jun 11 2023, 05:26:28) [GCC 11.4.0


## Using Conda

Ongoing work  to get SWI-Prolog  working under  Conda can be  found at
https://github.com/SWI-Prolog/swi-prolog-feedstock.   Eventually, this
work shall be merged with https://anaconda.org/conda-forge/swi-prolog

As  is,  https://github.com/SWI-Prolog/swi-prolog-feedstock  has  been
used  to build  the full  SWI-Prolog  system with  Janus interface  on
Linux, MacOS and Windows.


## Alternatives

### MQI (Machine Query Interface)

SWI-Prolog               comes              bundled               with
[MQI](https://www.swi-prolog.org/pldoc/package/mqi).  MQI is initiated
from  Python and  starts SWI-Prolog  as a  server.  It  allows calling
Prolog from Python.  Separated using networking, this approach is easy
to  install and  runs  with any  Python version.   It  does not  allow
calling Python  from Prolog, the  primary reason for the  existence of
this package.  Using networking, the latency is relatively high.

### pyswip

The   [pyswip](https://github.com/yuce/pyswip)   interface  uses   the
[Python    ctypes](https://docs.python.org/3/library/ctypes.html)   to
embed Prolog into Python.  Only relying  on _ctypes_, the package is a
fully portable Python package that supports a wide range of Python and
Prolog versions.

Unlike this  package, embedding  Python into  Prolog is  not possible.
_pyswip_ calls Prolog, similarly than janus, using a string.  However,
where  janus allows  passing input  to the  goal as  a _dict_  that is
transferred using the C API  rather than strings, _pyswip_ also passes
the  input as  a  string.   This is  slower,  sensitive to  _injection
attacks_  and   complicated  because  the  user   is  responsible  for
generating  valid Prolog  syntax.   Calls from  Prolog  to Python  are
possible by defining a Prolog  predicate from Python.  This only seems
to support  deterministic predicates and  it cannot pass data  back to
Prolog.  Janus supports calling  Python functions and methods directly
and  supports  enumerating  Python  _iterators_  and  _generators_  as
non-deterministic goals using py_iter/2.

The  overhead of  Janus is  roughly 5  times less  than _pyswip_.   As
_pyswip_ still sustains over 100K  calls per second this is irrelevant
to many applications.


This file is an extract from the the online documentation at
https://github.com/stamparm/pcapy-ng/blob/master/README.md


What is Pcapy-NG?
=================

Pcapy-NG is a Python extension module that enables software written in
Python to access the routines from the pcap packet capture library. It is
a replacement of Pcapy, which is not maintained any more and stopped working
altogether on Python3.10.

From libpcap's documentation: "Libpcap is a system-independent
interface for user-level packet capture. Libpcap provides a portable
framework for low-level network monitoring. Applications include
network statistics collection, security monitoring, network debugging,
etc."

What makes pcapy different from the others?
-------------------------------------------

 * works with Python threads.
 * works both in UNIX with libpcap and Windows with WinPcap.
 * provides a simpler Object Oriented API.


Setup
=====

Quick start
-----------

Grab the latest stable release, unpack it and run 'python setup.py
install' from the directory where you placed it. Isn't that easy?


Requirements
------------

 * A Python interpreter. Versions 2.1.3 and newer are known to work.
 * A C++ compiler. GCC G++ 2.95, as well as Microsoft Visual Studio
   6.0, are known to work.
 * Libpcap 0.7.2 or newer. Windows user are best to check WinPcap 3.0
   or newer.
 * A recent release of Pcapy.

Compiling the source and installing
-----------------------------------

As this extension is written in C++ it needs to be compiled for the
host system before it can be accessed from Python. Fortunately this
process has been made easy by the setup.py script. In order to compile
and install the source execute the following command from the
directory where the pcapy's distribution has been unpacked: 'python
setup.py install'. This will install the extension into the default
Python's modules path; note that you might need special permissions to
write there. For more information on what commands and options are
available from setup.py, run 'python setup.py --help-commands'.

This extension has been tested under Linux and Windows systems
and is known to work there, but it ought to work out-of-the-box on any
system where Python and libpcap are available.


Licensing
=========

This software is provided under under the Apache Software License.
See the accompanying LICENSE file for more information.


Contact Us
==========

Whether you want to report a bug, send a patch or give some
suggestions on this package, drop a few lines at
miroslav@sqlmap.org.


========================================================
pyOpenSSL -- A Python wrapper around the OpenSSL library
========================================================

.. image:: https://readthedocs.org/projects/pyopenssl/badge/?version=stable
   :target: https://pyopenssl.org/en/stable/
   :alt: Stable Docs

.. image:: https://github.com/pyca/pyopenssl/workflows/CI/badge.svg?branch=main
   :target: https://github.com/pyca/pyopenssl/actions?query=workflow%3ACI+branch%3Amain

**Note:** The Python Cryptographic Authority **strongly suggests** the use of `pyca/cryptography`_
where possible. If you are using pyOpenSSL for anything other than making a TLS connection
**you should move to cryptography and drop your pyOpenSSL dependency**.

High-level wrapper around a subset of the OpenSSL library. Includes

* ``SSL.Connection`` objects, wrapping the methods of Python's portable sockets
* Callbacks written in Python
* Extensive error-handling mechanism, mirroring OpenSSL's error codes

... and much more.

You can find more information in the documentation_.
Development takes place on GitHub_.


Discussion
==========

If you run into bugs, you can file them in our `issue tracker`_.

We maintain a cryptography-dev_ mailing list for both user and development discussions.

You can also join ``#pyca`` on ``irc.libera.chat`` to ask questions or get involved.


.. _documentation: https://pyopenssl.org/
.. _`issue tracker`: https://github.com/pyca/pyopenssl/issues
.. _cryptography-dev: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _GitHub: https://github.com/pyca/pyopenssl
.. _`pyca/cryptography`: https://github.com/pyca/cryptography


<p align="center">
	<img width="105" height="176" src="./pypacker_logo_large.png">
</p>

[![Build Status](https://travis-ci.org/mike01/pypacker.svg?branch=master)](https://travis-ci.org/mike01/pypacker)
[![version](http://img.shields.io/pypi/v/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-versions](https://img.shields.io/pypi/pyversions/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-implementations](https://img.shields.io/pypi/implementation/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)

# General information
This is Pypacker: The fastest and simplest low-level packet manipulation library for Python.
See below examples for what you can do with it.

If you want to support this project you can [![Donate with PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=M6GGAXJQCUHVC&source=url) via PayPal.

## What you can do with Pypacker
Create custom Packets via keywords or from raw bytes and access/change their data:

```python
from pypacker.layer3 import ip
from pypacker.layer3 import icmp

# Packet via keywords
ip0 = ip.IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

# Packet from raw bytes. ip1_bts can also be retrieved via ip0.bin()
ip1_bts = b"E\x00\x00*\x00\x00\x00\x00@\x01;)\x7f\x00\x00\x01\xc0\xa8\x00\x01\x08\x00\xc0?\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00foobar"
ip1 = ip.IP(ip1_bts) 

# Output packet (similar result for ip1)
print("%s" % ip0)
layer3.ip.IP
        v_hl         (B): 0x45 = 69 = 0b1000101
        tos          (B): 0x0 = 0 = 0b0
        len          (H): 0x22 = 34 = 0b100010
        id           (H): 0x0 = 0 = 0b0
        frag_off     (H): 0x0 = 0 = 0b0
        ttl          (B): 0x40 = 64 = 0b1000000
        p            (B): 0x1 = 1 = 0b1 = IP_PROTO_ICMP
        sum          (H): 0x3B31 = 15153 = 0b11101100110001
        src          (4): b'\x7f\x00\x00\x01' = 127.0.0.1
        dst          (4): b'\xc0\xa8\x00\x01' = 192.168.0.1
        opts            : []
layer3.icmp.ICMP
        type         (B): 0x8 = 8 = 0b1000 = ICMP_ECHO
        code         (B): 0x0 = 0 = 0b0
        sum          (H): 0xC03F = 49215 = 0b1100000000111111
layer3.icmp.Echo
        id           (H): 0x7B = 123 = 0b1111011
        seq          (H): 0x1 = 1 = 0b1
        bodybytes    (6): b'foobar'

# Access any header fields on any layer
ip_dst = ip1.dst_s
icmp_type = ip1.higher_layer.type

# Access layers via advanced filter (e.g. on unknown packet structure)
ip0_found, icmp0_found, echo0_found = pkt[
	(None, lambda b: b.__class__ == ip.IP),
	icmp.ICMP,
	(icmp.ICMP.Echo, lambda b: b.id == 123)
]

if echo0_found is not None:
	print(echo0_found)

# Change source IPv4 address
ip1.src_s = "1.2.3.4"

# Change ICMP payload
ip1.highest_layer.body_bytes = b"foobar2"
```


Read/write packets from/to file (Support only for Wireshark/tcpdump pcap format):

```python
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp
from pypacker.layer567 import http

preader = ppcap.Reader(filename="ether.pcap")
pwriter = ppcap.Writer(filename="ether_new.pcap", linktype=ppcap.DLT_EN10MB)

for ts, buf in preader:
	pkt = ethernet.Ethernet(buf)

	# Filter specific packets
	eth0, ip0, tcp0, http0 = pkt[
		None,
		(None, lambda b: b.__class__ in [ip.IP, ip6.IP6]),
		(tcp.TCP, lambda c: c.dport==80),
		http.HTTP
	]

	if eth0 is not None:
		print(f"{ts}: {ip0.src_s}:{tcp0.sport} -> {ip0.dst_s}:{tcp0.dport}")
		pwriter.write(eth0.bin())

pwriter.close()
```

Merge multiple pcap files to one file. Tries to read corrupted pcap files and allows filtering by pypacker callback.
```
from pypacker import ppcap
from pypacker.layer4 import tcp

def filter_accept(bts):
    # Get all TCP packets
    pkt = ethernet.Ethernet(bts)
    return pkt[tcp.TCP] is not None

ppcap.merge_pcaps(["file_in1.pcap", "file_in2.pcap"], "file_out.pcap", filter_accept=filter_accept)
```

Send/receive layer 2 (and higher)  packets:

```python
from pypacker import psocket
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

psock = psocket.SocketHndl(timeout=10)

def filter_pkt(pkt):
	return pkt[None, ip.IP, (tcp.TCP, lambda p: p.sport == 80)][2] is not None

# Receive raw bytes
for raw_bytes in psock:
	eth = ethernet.Ethernet(raw_bytes)
	print("Got packet: %r" % eth)
	eth.reverse_address()
	eth.higher_layer.reverse_address()
	# Send bytes
	psock.send(eth.bin())
	# Receive (any) raw bytes
	bts = psock.recv()
	# Send/receive based on source/destination data in packet
	pkts = psock.sr(eth)
	# Use filter to get specific packets
	pkts = psock.recvp(filter_match_recv=filter_pkt)
	# stop on first packet
	break

psock.close()
```

Intercept (and modificate) Packets e.g. for MITM:

```python
# Add iptables rule:
# iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
# Alternatively add nftables rule:
# nft add table inet pptable
# nft add chain inet pptable filter { type filter hook input priority 0 \; policy accept\; }
# nft add rule inet pptable filter counter queue num 0-2
import time

from pypacker import interceptor
from pypacker.layer3 import ip, icmp

# ICMP Echo request intercepting
def verdict_cb(ll_data, ll_proto_id, data, ctx, *args):
	ip1 = ip.IP(data)
	icmp1 = ip1[icmp.ICMP]

	if icmp1 is None or icmp1.type != icmp.ICMP_ECHO:
		return data, interceptor.NF_ACCEPT

	echo1 = icmp1[icmp.ICMP.Echo]

	if echo1 is None:
		return data, interceptor.NF_ACCEPT

	pp_bts = b"PYPACKER"
	print("changing ICMP echo request packet")
	echo1.body_bytes = echo1.body_bytes[:-len(pp_bts)] + pp_bts
	return ip1.bin(), interceptor.NF_ACCEPT

ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2])
print("now sind a ICMP echo request to localhost: ping 127.0.0.1")
time.sleep(999)
ictor.stop()
```


## Prerequisites
- Python 3.x (CPython, Pypy, Jython or whatever Interpreter)
- Optional: netifaces >=0.10.6 (for utils)
- Optional (for interceptor):
  - CPython
  - Linux based system with kernel support for NFQUEUE target. The kernel config option is at:
	- Networking Options -> Network packet filtering -> Core Netfilter -> NFQUEUE target
  - iptables (alternatively nftables)
    - NFQUEUE related rulez can be added eg "iptables -I INPUT 1 -j NFQUEUE --queue-num 0"
  - libnetfilter_queue library (see http://www.netfilter.org/projects/libnetfilter_queue)

## Installation
Some examples:
- Clone newest version
  - git clone https://gitlab.com/mike01/pypacker.git
  - cd pypacker
  - python setup.py install
- Use pip (synched to master on major version changes)
  - pip install pypacker

## Usage examples and documentation
See:

- Above examples
- Examples in directory ./examples
- Gitlab Wiki: https://gitlab.com/mike01/pypacker/-/wikis/home

Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
by their respective RFCs/official standards.

## Testing
Tests are executed as follows:

1) Add Pypacker directory to the PYTHONPATH.

- `cd pypacker`
- `export PYTHONPATH=$(pwd):$PYTHONPATH`

2) Execute tests

- `python tests/test_pypacker.py`

**Performance test results:**
```
Hardware: Intel CPU, 4 Cores @ 3.2 GHz
Python: CPython v3.10.13

nr = new results on this machine
rounds per test: 10000
=====================================
>>> Packet parsing (Ethernet + IP + UDP + DNS): Search UDP port
Time diff: 0.3220548629760742s
nr = 31050 p/s
>>> Packet parsing (Ethernet + IP + TCP + HTTP): Search TCP port
Time diff: 0.5902166366577148s
nr = 16942 p/s
>>> Packet parsing (Ethernet + IP + TCP + HTTP): Reading all header
Time diff: 0.9773461818695068s
nr = 10231 p/s
>>> Parsing first layer (IP + ICMP)
Time diff: 0.04322528839111328s
nr = 231346 p/s
>>> Creating/direct assigning (IP only header)
Time diff: 0.06982040405273438s
nr = 143224 p/s
>>> bin() without change (IP)
Time diff: 0.02322697639465332s
nr = 430533 p/s
>>> Output with change/checksum recalculation (IP)
Time diff: 0.18998193740844727s
nr = 52636 p/s
>>> Basic/first layer parsing (Ethernet + IP + TCP + HTTP)
Time diff: 0.048027992248535156s
nr = 208211 p/s
>>> Changing Triggerlist element value (Ethernet + IP + TCP + HTTP)
Time diff: 0.04828596115112305s
nr = 207099 p/s
>>> Changing dynamic field (Ethernet + IP + TCP + HTTP)
Time diff: 0.016223669052124023s
nr = 616383 p/s
>>> Direct assigning and concatination (Ethernet + IP + TCP + HTTP)
Time diff: 0.3817322254180908s
nr = 26196 p/s
>>> Performance test pypacker vs. dpkt vs. scapy
Comparing pypacker, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)
nr = new results on this machine
rounds per test: 10000
>>> testing pypacker parsing speed
nr = 74695 p/s
Could not execute dpkt tests: ModuleNotFoundError("No module named 'dpkt'")
>>> testing scapy parsing speed
nr = 1732 p/s
```

# FAQ

For any questions left please file a bug (will be tagged as "questions").

**Q**:	How fast is pypacker?

**A**:	See results above. For detailed results on your machine execute tests:
	`python tests/test_pypacker.py PerfTestCase`

**Q**:	Which protocols are supported?

**A**:	Currently minimum supported protocols are:
	Ethernet, Radiotap, IEEE80211, ARP, DNS, STP, PPP, OSPF, VRRP, DTP, IP, ICMP, PIM, IGMP, IPX,
	TCP, UDP, SCTP, HTTP, NTP, RTP, DHCP, RIP, SIP, Telnet, HSRP, Diameter, SSL, TPKT, Pmap, Radius, BGP

**Q**:	Are there any plans to support [xyz]?

**A**:	New features are added to Pypacker as a result of me needing them or people contributing
	them - no formal plans for adding support for particular features in future releases exist.
	A general guideline for contribution can be found in the file HACKING.

**Q**:	How can I contribute to this project?

**A**:	Please use the Gitlab bug-tracker for bugs/feature request. Please read the bugtracker for
	already known bugs before filing a new one. Patches can be send via pull request.

**Q**:	There is problem xyz with Pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	The basic features should work with any OS. Optional ones may make trouble (eg interceptor).

**Q**:	Under which license Pypacker is issued?

**A**:	It's the GPLv2 License (see LICENSE file for more information).

**Q**:	Calling copy.deepcopy(some_packet) raises an exception "TypeError: can't pickle Struct objects".

**A**:	Try the following workaround to be able to pickle Struct objects:
```python
import struct, copyreg
def pickle_struct(s):
	return struct.Struct, (s.format,)

copyreg.pickle(struct.Struct, pickle_struct)
```


# Usage hints
## Performance related
- For maxmimum performance start accessing attributes at lowest level via the following index notation.
  This will lazy parse only needed layers behind the scenes:
```
pkt_eth, pkt_ip, pkt_tcp, pkt_http = pkt[
  None,
  (None, lambda b: b.__class__ in [ip.IP, ip6.IP6]),
  (tcp.TCP, lambda c: c.dport==80),
  http.HTTP
]
...
```

- Avoid to convert packets using the "%s" or "%r" format as it triggers parsing behind the scene:
```
pkt = Ethernet() + IP() + TCP()
# This parses ALL layers
packet_print = "%s" % pkt
```

- Avoid searching for a layer using single-value index-notation via pkt[L] as it parses all layers until L is found or highest layer is reached:
```
packet_found = pkt[Telnet]
# Alternative: Use multi-value index-notation. This will stop parsing at any non-matching layer:
packet_found = pkt[Ethernet,IP,TCP,Telnet]
```

- Use pypy (~3x faster than CPython related to full packet parsing)

- For even more performance disable auto fields (affects calling bin(...)):
```
pkt = ip.IP(src_s="1.2.3.4", dst_s="1.2.3.5") + tcp.TCP()
# Disable checksum calculation (and any other update) for IP and TCP (only THIS packet instance)
pkt.sum_au_active = False
pkt.tcp.sum_au_active = False
bts = pkt.bin(update_auto_fields=False)
```

- Enlarge receive/send buffers to get max performance. This can be done using the following commands
	(taken from: http://www.cyberciti.biz/faq/linux-tcp-tuning/):
```
sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.rmem_default=12582912
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.wmem_default=12582912
sysctl -w net.core.optmem_max=2048000
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.unix.max_dgram_qlen=1000
sysctl -w net.ipv4.tcp_rmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_wmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_mem="21228 87380 12582912"
sysctl -w net.ipv4.udp_mem="21228 87380 12582912"
sysctl -w net.ipv4.tcp_window_scaling=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.ipv4.tcp_sack=1
```

## Misc related
- Assemblation of TCP/UDP streams can be done by tshark using pipes
	with "-i -" and "-z follow,prot,mode,filter[,range]"
- Chosing the right "lowest layer" when reading capture files: Open the file eg w/ wireshark
  and look at the packet details for the data link layer. Most times this will probably
  be Ethernet II which can be parsed w/ layer12.ethernet.Ethernet.
  When capturing eg via wiresharks/tsharks "-i any" option, this will lead to Linux cooked capture
  represented by layer12.linuxcc.LinuxCC.


<div align="center">
  <img src="https://storage.googleapis.com/tf_model_garden/tf_model_garden_logo.png">
</div>

[![Python](https://img.shields.io/pypi/pyversions/tensorflow.svg?style=plastic)](https://badge.fury.io/py/tensorflow)
[![tf-models-official PyPI](https://badge.fury.io/py/tf-models-official.svg)](https://badge.fury.io/py/tf-models-official)


# Welcome to the Model Garden for TensorFlow

The TensorFlow Model Garden is a repository with a number of different
implementations of state-of-the-art (SOTA) models and modeling solutions for
TensorFlow users. We aim to demonstrate the best practices for modeling so that
TensorFlow users can take full advantage of TensorFlow for their research and
product development.

To improve the transparency and reproducibility of our models, training logs on
[TensorBoard.dev](https://tensorboard.dev) are also provided for models to the
extent possible though not all models are suitable.

| Directory | Description |
|-----------|-------------|
| [official](official) | • A collection of example implementations for SOTA models using the latest TensorFlow 2's high-level APIs<br />• Officially maintained, supported, and kept up to date with the latest TensorFlow 2 APIs by TensorFlow<br />• Reasonably optimized for fast performance while still being easy to read<br /> For more details on the capabilities, check the guide on the [Model-garden](https://www.tensorflow.org/tfmodels)|
| [research](research) | • A collection of research model implementations in TensorFlow 1 or 2 by researchers<br />• Maintained and supported by researchers |
| [community](community) | • A curated list of the GitHub repositories with machine learning models and implementations powered by TensorFlow 2 |
| [orbit](orbit) | • A flexible and lightweight library that users can easily use or fork when writing customized training loop code in TensorFlow 2.x. It seamlessly integrates with `tf.distribute` and supports running on different device types (CPU, GPU, and TPU). |

## Installation

To install the current release of tensorflow-models, please follow any one of the methods described below.

#### Method 1: Install the TensorFlow Model Garden pip package

<details>

**tf-models-official** is the stable Model Garden package. Please check out the [releases](https://github.com/tensorflow/models/releases) to see what are available modules.

pip3 will install all models and dependencies automatically.

```shell
pip3 install tf-models-official
```

Please check out our examples:
  - [basic library import](https://github.com/tensorflow/models/blob/master/tensorflow_models/tensorflow_models_pypi.ipynb)
  - [nlp model building](https://github.com/tensorflow/models/blob/master/docs/nlp/index.ipynb)
to learn how to use a PIP package.

Note that **tf-models-official** may not include the latest changes in the master branch of this
github repo. To include latest changes, you may install **tf-models-nightly**,
which is the nightly Model Garden package created daily automatically.

```shell
pip3 install tf-models-nightly
```

</details>


#### Method 2: Clone the source

<details>

1. Clone the GitHub repository:

```shell
git clone https://github.com/tensorflow/models.git
```

2. Add the top-level ***/models*** folder to the Python path.

```shell
export PYTHONPATH=$PYTHONPATH:/path/to/models
```

If you are using in a Windows environment, you may need to use the following command with PowerShell:
```shell
$env:PYTHONPATH += ":\path\to\models"
```

If you are using a Colab notebook, please set the Python path with os.environ.

```python
import os
os.environ['PYTHONPATH'] += ":/path/to/models"
```

3. Install other dependencies

```shell
pip3 install --user -r models/official/requirements.txt
```

Finally, if you are using nlp packages, please also install
**tensorflow-text-nightly**:

```shell
pip3 install tensorflow-text-nightly
```

</details>


## Announcements

Please check [this page](https://github.com/tensorflow/models/wiki/Announcements) for recent announcements.

## Contributions

[![help wanted:paper implementation](https://img.shields.io/github/issues/tensorflow/models/help%20wanted%3Apaper%20implementation)](https://github.com/tensorflow/models/labels/help%20wanted%3Apaper%20implementation)

If you want to contribute, please review the [contribution guidelines](https://github.com/tensorflow/models/wiki/How-to-contribute).

## License

[Apache License 2.0](LICENSE)

## Citing TensorFlow Model Garden

If you use TensorFlow Model Garden in your research, please cite this repository.

```
@misc{tensorflowmodelgarden2020,
  author = {Hongkun Yu, Chen Chen, Xianzhi Du, Yeqing Li, Abdullah Rashwan, Le Hou, Pengchong Jin, Fan Yang,
            Frederick Liu, Jaeyoun Kim, and Jing Li},
  title = {{TensorFlow Model Garden}},
  howpublished = {\url{https://github.com/tensorflow/models}},
  year = {2020}
}
```
