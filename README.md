# Advanced Network Forensics and AI Vulnerability Detection System

## Overview
This project integrates advanced tools and techniques for network forensics, vulnerability detection, and AI-driven expert systems. It leverages the capabilities of:

- **CORE**: An expert system for functional analysis and reasoning.
- **INTERFACE_BUFFER**: A system for sophisticated data processing and analysis.
- **INFERENCE ENGINE**: An English Engine for Grammar, used for natural language processing and understanding.

## Features
- **Network Forensics**: Utilize CORE and Dshell for in-depth network data analysis and pattern recognition.
- **Vulnerability Detection**: Train and deploy TensorFlow models to identify and assess potential vulnerabilities.
- **AI Expert System**: Employ Interface_Buffer and Inference_Engine for advanced decision-making and natural language processing.

## Installation
1. **Clone the Repository:**
    ```bash
    git clone https://github.com/functionals/hydrawall/
    ```

2. **Navigate to the Project Directory:**
    ```bash
    cd your-repository
    ```

3. **Set Up a Virtual Environment (Optional but recommended):**
    ```bash
    python -m venv env
    source env/bin/activate  # On Windows use `env\Scripts\activate`
    ```


## Usage

### Network Forensics
Run the CORE for network forensics analysis:

###Train the TensorFlow model with Dshell.trainingpack



###Run Vulnerability Analysis

# Supplements

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
# Public docs for TensorFlow Models

This directory contains the top-level public documentation for
[TensorFlow Models](https://github.com/tensorflow/models).

This directory is mirrored to https://tensorflow.org/tfmodels, and is mainly
concerned with documenting the tools provided in the `tensorflow_models` pip
package (including `orbit`).

Api-reference pages are
[available on the site](https://www.tensorflow.org/api_docs/more).

The
[Official Models](https://github.com/tensorflow/models/blob/master/official/projects)
and [Research Models](https://github.com/tensorflow/models/blob/master/research)
directories are not described in detail here, refer to the individual project
directories for more information.

=======
 janus
=======
.. image:: https://github.com/aio-libs/janus/actions/workflows/ci.yml/badge.svg
    :target: https://github.com/aio-libs/janus/actions/workflows/ci.yml
.. image:: https://codecov.io/gh/aio-libs/janus/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/aio-libs/janus
.. image:: https://img.shields.io/pypi/v/janus.svg
    :target: https://pypi.python.org/pypi/janus
.. image:: https://badges.gitter.im/Join%20Chat.svg
    :target: https://gitter.im/aio-libs/Lobby
    :alt: Chat on Gitter



Mixed sync-async queue, supposed to be used for communicating between
classic synchronous (threaded) code and asynchronous (in terms of
asyncio_) one.

Like `Janus god <https://en.wikipedia.org/wiki/Janus>`_ the queue
object from the library has two faces: synchronous and asynchronous
interface.

Synchronous is fully compatible with `standard queue
<https://docs.python.org/3/library/queue.html>`_, asynchronous one
follows `asyncio queue design
<https://docs.python.org/3/library/asyncio-queue.html>`_.

Usage example (Python 3.7+)
===========================

.. code:: python

    import asyncio
    import janus


    def threaded(sync_q: janus.SyncQueue[int]) -> None:
        for i in range(100):
            sync_q.put(i)
        sync_q.join()


    async def async_coro(async_q: janus.AsyncQueue[int]) -> None:
        for i in range(100):
            val = await async_q.get()
            assert val == i
            async_q.task_done()


    async def main() -> None:
        queue: janus.Queue[int] = janus.Queue()
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(None, threaded, queue.sync_q)
        await async_coro(queue.async_q)
        await fut
        queue.close()
        await queue.wait_closed()


    asyncio.run(main())


Usage example (Python 3.5 and 3.6)
==================================
**N.B. For python 3.6 and below you must use janus < 1.0.0**

.. code:: python

    import asyncio
    import janus

    loop = asyncio.get_event_loop()


    def threaded(sync_q):
        for i in range(100):
            sync_q.put(i)
        sync_q.join()


    async def async_coro(async_q):
        for i in range(100):
            val = await async_q.get()
            assert val == i
            async_q.task_done()


    async def main():
        queue = janus.Queue()
        fut = loop.run_in_executor(None, threaded, queue.sync_q)
        await async_coro(queue.async_q)
        await fut
        queue.close()
        await queue.wait_closed()

    try:
        loop.run_until_complete(main())
    finally:
        loop.close()


Communication channels
======================

GitHub Discussions: https://github.com/aio-libs/janus/discussions

Feel free to post your questions and ideas here.

*gitter chat* https://gitter.im/aio-libs/Lobby


License
=======

``janus`` library is offered under Apache 2 license.

Thanks
======

The library development is sponsored by DataRobot (https://datarobot.com)

.. _asyncio: https://docs.python.org/3/library/asyncio.html



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
