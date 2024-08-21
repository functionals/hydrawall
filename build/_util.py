# -*- coding: utf-8 -*-
"""
Created on Sat Aug 17 20:09:43 2024

@author: United States Army Research Lab, Ian Malloy
"""
import os
import sys
import warnings
from typing import Any, Callable, NoReturn, Type, Union

from cryptography.hazmat.bindings.openssl.binding import Binding

# Type alias for file paths
StrOrBytesPath = Union[str, bytes, os.PathLike]

# Initialize OpenSSL bindings
binding = Binding()
ffi = binding.ffi
lib = binding.lib

# Special CFFI allocator for improved performance
no_zero_allocator = ffi.new_allocator(should_clear_after_alloc=False)

def text(charp: Any) -> str:
    """
    Convert a C-style string represented by a CFFI ``char*`` to a Python string.

    :param charp: A C-style string represented using CFFI.
    :return: A Python string.
    """
    if not charp:
        return ""
    return ffi.string(charp).decode("utf-8")

def exception_from_error_queue(exception_type: Type[Exception]) -> NoReturn:
    """
    Convert an OpenSSL library failure into a Python exception.

    Retrieves error codes and messages from the OpenSSL error queue and raises
    an exception with this information.

    :param exception_type: The type of exception to raise.
    """
    errors = []
    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        errors.append((
            text(lib.ERR_lib_error_string(error)),
            text(lib.ERR_func_error_string(error)),
            text(lib.ERR_reason_error_string(error)),
        ))
    raise exception_type(errors)

def make_assert(error: Type[Exception]) -> Callable[[bool], None]:
    """
    Create an assert function that raises an exception if a condition is not met.

    :param error: The exception type to raise if the condition is not met.
    :return: An assertion function.
    """
    def openssl_assert(ok: bool) -> None:
        """
        Raise an exception if `ok` is not True.
        """
        if not ok:
            exception_from_error_queue(error)

    return openssl_assert

def path_bytes(s: StrOrBytesPath) -> bytes:
    """
    Convert a path to bytes for use with OpenSSL APIs.

    :param s: A path (valid for os.fspath).
    :return: A bytes representation of the path.
    """
    b = os.fspath(s)
    if isinstance(b, str):
        return b.encode(sys.getfilesystemencoding())
    return b

def byte_string(s: str) -> bytes:
    """
    Convert a string to bytes using 'charmap' encoding.

    :param s: A string.
    :return: A bytes representation of the string.
    """
    return s.encode("charmap")

# Marker object for unspecified optional arguments
UNSPECIFIED = object()

_TEXT_WARNING = "str for {0} is no longer accepted, use bytes"

def text_to_bytes_and_warn(label: str, obj: Any) -> Any:
    """
    Emit a warning and convert text to bytes if necessary.

    :param label: The name of the parameter for context in the warning.
    :param obj: The object to check and convert.
    :return: A bytes representation if `obj` is a string, otherwise `obj` itself.
    """
    if isinstance(obj, str):
        warnings.warn(
            _TEXT_WARNING.format(label),
            category=DeprecationWarning,
            stacklevel=3,
        )
        return obj.encode("utf-8")
    return obj




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