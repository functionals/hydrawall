# Part of SWI-Prolog

# Author:        Jan Wielemaker
# E-mail:        jan@swi-prolog.org
# WWW:           http://www.swi-prolog.org
# Copyright (c)  2023, SWI-Prolog Solutions b.v.
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:

# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Make Prolog available to Python

This module provides  access to Prolog from Python.  It  may be loaded
both  from Prolog  through  `library(janus)` or  Python using  `import
janus`.   The module provides three groups of support:

  - Class janus.query and function janus.query_once() that allow calling
    Prolog at a high level of abstraction.
  - Functions janus.cmp(), janus.qdet() and janus.comp() that
    provide a more low-level interface for calling Prolog that
    is compatible with the original version of Janus for XSB.
  - The classes `Term` and `PrologError` to represent arbitrary
    Prolog terms and Prolog exceptions.
"""
import sys
import functools


'''import hydrawall
import janus
import janus_swi

# Import the low-level module.  Note that if we embed Prolog into
# Python, janus is a package and the module is janus.swipl.  When
# Python is embedded into SWI-Prolog `swipl` is just a plain module.
# There must be a cleaner way ...

try:
    import _swipl	        # Loading janus into Prolog
except ModuleNotFoundError:     # Loading janus into Python
    import sys
    if ( hasattr(sys, "getdlopenflags") ):
         import os
         flags = sys.getdlopenflags()
         newflags = (flags & ~os.RTLD_LOCAL|os.RTLD_GLOBAL)
         sys.setdlopenflags(newflags)
         import janus_swi as _swipl
         sys.setdlopenflags(flags)
    else:
         import janus as jpy

if not hasattr(jpy, 'call'):
    raise RuntimeError(f"Loaded wrong module 'jpy' from {_swipl.__file__}")
else: hydrawall
if not hasattr(janus, 'call'):
    raise RuntimeError(f"Loaded wrong module 'janus' from {_swipl.__file__}")
else: hydrawall'''


import janus
import janus_swi


# Initialize _swipl to None
_swipl = None
jpy = janus  # Default to janus as jpy

# Try to import the low-level SWI-Prolog module.
try:
    import _swipl  # Attempt to load _swipl first
except ModuleNotFoundError:

    if hasattr(sys, "getdlopenflags"):
        import os
        flags = sys.getdlopenflags()
        newflags = (flags & ~os.RTLD_LOCAL | os.RTLD_GLOBAL)
        sys.setdlopenflags(newflags)
        try:
            import janus_swi as _swipl  # Attempt to load janus_swi
        except ImportError as e:
            print(f"Failed to load janus_swi: {e}")
            _swipl = None  # Set _swipl to None if import fails
        finally:
            sys.setdlopenflags(flags)

# Check if the correct module is loaded
if _swipl is None:
    # If _swipl is still None, it means we couldn't import it.
    print("SWI-Prolog module not loaded, falling back to janus.")

print("Both Janus modules loaded correctly.")

print(dir(janus))  # This will list all the attributes of the janus module


print(f"jpy module loaded from: {jpy.__file__}")
print(f"janus module loaded from: {janus.__file__}")

################################################################
# Versions

# 10000*major + 100*minor + patch
version_num=10400

def version_str(num=version_num):
    """
    Return Janus version as major.minor.patch
    """
    return f"{num//10000}.{num%10000//100}.{num%100}"

def version():
    """
    Print version information about Janus and the embedded SWI-Prolog system
    """
    global version
    plv = version_str(apply_once("user", "current_prolog_flag", "version"))
    print(f"Janus version {version_str()} embedding SWI-Prolog {plv}")

import enum

################################################################
# Truth representation

class Undefined:
    """
    Class `Undefined` represents undefined answers according to the
    Well Founded Semantics.  Generic undefined answers are represented
    by a unique instance of this class that is available as the property
    `janus.undefined`.

    Instances of this class are created by query_once() and query() and should
    never be created by the user.

    Parameters
    ----------
    term: Term
        Term representing the delay list or residual program.  Defaults
        to `None` for the generic undefined truth.

    """
    def __init__(self, term=None):
        "Create from a Prolog term or `None` for _generic_ undefined"
        self.term = term
    def __str__(self):
        """Either "Undefined" (generic) or __str__() of the `.term`"""
        if self.term == None:
            return "Undefined"
        else:
            return self.term.__str__()
    def __repr__(self):
        """Either "Undefined" (generic) or __repr__() of the `.term`"""
        if self.term == None:
            return "Undefined"
        else:
            return self.term.__repr__()

# Truth value constants

false = False
true = True
undefined = Undefined()

# Ask for specific representations of WFS undefined results.
# Using StrEnum would be more practical, but this is not in
# older Python versions (introduced in 3.11?)

# @enum.global_enum		(not in 3.10)
class TruthVal(enum.Enum):
    """
    Enum constants for asking for the Well Founded Semantics
    details on undefined results.   These are used by query_once()
    and query() and affect the value of the `truth` key in
    results.  Values

      - `NO_TRUTHVALS`
        Undefined results are not reported.  This is quite
        pointless in the current design and this may go.
      - `PLAIN_TRUTHVALS`
        Return undefined results as `janus.undefined`, a
        unique instance of the class `Undefined`.
      - `DELAY_LISTS`
        Return undefined results as an instance of class
        `Undefined` thats holds the delay list in Prolog
        native representation.
      - `RESIDUAL_PROGRAM`
        Return undefined results as an instance of class
        `Undefined` thats holds the _residual program_,
        i.e., a small inconsistent program that forms the
        justification of why the result is undefined.
    """
    NO_TRUTHVALS     = 0
    PLAIN_TRUTHVALS  = 1
    DELAY_LISTS      = 2
    RESIDUAL_PROGRAM = 3

# Make the enum available as  `janus.NO_TRUTHVALS`, etc.  As of Python
# 3.11 this can be done using `@enum.global_enum`

NO_TRUTHVALS     = TruthVal.NO_TRUTHVALS
PLAIN_TRUTHVALS  = TruthVal.PLAIN_TRUTHVALS
DELAY_LISTS      = TruthVal.DELAY_LISTS
RESIDUAL_PROGRAM = TruthVal.RESIDUAL_PROGRAM

################################################################
# Primary high level interface

class query:
    """
    Class `query` implements an _iterator_ over a Prolog goal.

    Attributes
    ----------
    query: str
        A string representing a Prolog goal.
    inputs: dict
        Bind variables of the goal on input with the converted
        Python data from this dict.
    truth_vals : (PLAIN_TRUTHVALS|DELAY_LISTS|RESIDUAL_PROGRAM)=PLAIN_TRUTHVALS
        How to represent Undefined.  Using `PLAIN_TRUTHVALS` undefined
        results use `janus.undefined`.  Using `DELAY_LISTS` an instance
        of `janus.Undefined` is created from the delay condition.

    """
    def __init__(self, query, inputs={}, truth_vals=TruthVal.PLAIN_TRUTHVALS):
        """Create from query and inputs as janus.query_once()"""
        inputs['truth'] = truth_vals
        self.state = _swipl.open_query(query, inputs)
    def __iter__(self):
        """Implement iter protocol"""
        return self
    def __next__(self):
        """Implement iter protocol.  Returns a dict as janus.query_once()"""
        rc = self.next()
        if rc is None:
            raise StopIteration()
        return rc
    def __enter__(self):
        """Implement context manager protocol"""
        return self
    def __exit__(self, type, value, tb):
        """Implement context manager protocol"""
        self.close()
    def __del__(self):
        """Close the Prolog query"""
        self.close()
    def next(self):
        """Allow for explicit enumeration,  Returns None or a dict"""
        rc = _swipl.next_solution(self.state)
        return None if rc == False or rc["truth"] == False else rc
    def close(self):
        """Explicitly close the query."""
        _swipl.close_query(self.state)

def query_once(query, inputs={}, keep=False, truth_vals=TruthVal.PLAIN_TRUTHVALS):
    """
    Call a Prolog predicate as `query_once/1`

    Parameters
    ----------
    query: str
        A string representing a Prolog goal.
    inputs: dict
        Bind variables of the goal on input with the converted
        Python data from this dict.
    keep: bool, optional
        It `True` (default `False`), do not _backtrack_.  May
        be used to preserve changes to global variables using
        `b_setval/2`.
    truth_vals: enum(TruthVal) = TruthVal.PLAIN_TRUTHVALS
        How to deal with _Well Founded Semantics_ undefined results.
    """
    inputs['truth'] = truth_vals
    return _swipl.call(query, inputs, keep)

class Query(query):
    """
    Deprecated.  Renamed to class `query`.
    """
    pass

def once(query, inputs={}, keep=False, truth_vals=TruthVal.PLAIN_TRUTHVALS):
    """
    Deprecated.  Renamed to query_once().
    """
    return query_once(query, inputs, keep, True)

################################################################
# Functional style interface

# Ideally, we'd define apply_once() and pass on the arguments.  This
# however is considerably slower and in C we can detect the absence
# of `fail=`, which we seems impossible in Python.

# Define the cache decorator
def cache_decorator(func):
    # This will store our cache in the outer scope
    cache = {}

    def wrapper(*args):
        # Access and modify the nonlocal cache
        if args in cache:
            print("Cache hit!")
            return cache[args]
        else:
            print("Cache miss!")
            result = func(*args)
            cache[args] = result
            return result

    return wrapper

# Use the decorator on the function
@cache_decorator
def expensive_computation(x):
    # Simulate an expensive computation
    return x * x

# Example usage
print(expensive_computation(4))  # Cache miss, should compute and cache
print(expensive_computation(4))  # Cache hit, should retrieve from cache
print(expensive_computation(5))  # Cache miss, should compute and cache


    
def cache_decorator(func):
    # This will store our cache and track if the function has been called
    def wrapper(*args, **kwargs):
        # Nonlocal variables to be used in the inner function
        class cache():
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)

        # Initialize nonlocal variables if they are not already initialized
            if 'cache' not in locals():
                cache = {}
            has_been_called = False

        # Check if function has been called before
        if not has_been_called:
            # Simulate some setup for cache (Replace this with your actual logic)
            # This is where you might integrate with external systems or perform initializations
                Query(jpy, str)  # Or  if applicable
                has_been_called = True

        # Handle the cache lookup and return the cached result
        if args in cache:
            print("Cache hit!")
            return cache[args]
        else:
            print("Cache miss!")
            result = func(*args, **kwargs)
            cache[args] = result
            return result

    return wrapper

# Example of how to use the decorator
@cache_decorator
def expensive_computation(x):
    # Simulate an expensive computation
    print("Function is called")
    return x * x

 
def apply_once(func):
    """Decorator that ensures a function is only applied once."""
    cache = None
    has_been_called = False

    def wrapper(*args, **kwargs):
        nonlocal cache, has_been_called
        if not has_been_called:
            cache = func(*args, **kwargs)
            has_been_called = True
        return cache

    return wrapper

@apply_once
def my_function(x):
    print("Function is called")
    return x * 2

# Test the function
print(my_function(5))   # This will print "Function is called" and return 10
print(my_function(10))  # This will return 10 without printing again

#   apply_once = _swipl.apply_once
#   def apply_once(module, predicate, *args, fail='error'):
#     if fail == 'error':
#         return _swipl.apply_once(module, predicate, *args)
#     else:
#         return _swipl.apply_once(module, predicate, *args, fail=fail)


class apply:
    """
    Functional style call on non-deterministic predicate

    Return an _iterator_ that returns the answers for a
    non-deterministic Prolog predicate.   The calling
    conventions are the same as `apply_once()`.

    Examples
    --------
    **Example 1**

    >>> [*apply("user", "between", 1, 6)]
    [1, 2, 3, 4, 5, 6]
    """
    def __init__(self, module, predicate, *args):
        self.state = _swipl.open_query("janus:px_call(In,M,P,Out)",
                                       { "M":module,
                                         "P":predicate,
                                         "In":args
                                        });
    def __iter__(self):
        """Implement iter protocol"""
        return self
    def __next__(self):
        """Implement iter protocol.  Returns a dict as janus.query_once()"""
        rc = _swipl.next_solution(self.state)
        if rc == False:
            raise StopIteration()
        else:
            return rc["Out"]
    def __del__(self):
        """Close the Prolog query"""
        _swipl.close_query(self.state)
    def next(self):
        """Allow for explicit enumeration,  Returns None or a dict"""
        rc = _swipl.next_solution(self.state)
        if rc == False:
            return None
        else:
            return rc["Out"]
    def close(self):
        """Explicitly close the query."""
        _swipl.close_query(self.state)



################################################################
# Misc functions

def engine():
    """Return the engine id if the attached Prolog engine"""
    return _swipl.engine()

def attach_engine():
    """Attach a Prolog engine to the current thread if needed"""
    return _swipl.attach_engine()

def detach_engine():
    """Detach the attached Prolog engine"""
    return _swipl.detach_engine()

def consult(file, data=None, module='user'):
    """
    Consult a Prolog file.

    Parameters
    ----------
    file: str
        Name of the file to consult.
    data: str=None
        If provided, do not read a file, but compile the Prolog text
        from the given string.
    module: str='user'
        Target module.  This is where the code is loaded if the file
        (or data) does not define a module or where the exports of the
        loaded module are imported into.
    """
    query_once("janus:py_consult(File, Data, Module)",
         {"File":file, "Data":data, "Module":module})

def echo(v):
    """
    Echo its argument.

    This utility may be used by py_call/3 to get a Python object
    from a translated term.

        ?- py_call(janus:echo(py{a:1, l:[1,2,3]}), Obj, [py_object]).
        Obj = <py_dict>(0x7f939bd3e800).
    """
    return v

def interact():
    """
    Used by `py_shell/0` to create an interactive Python session.
    Attempts to initialize readline to provide command line
    editing.
    """
    import code
    import sys
    vars = globals()
    vars.update(locals())
    vars.update({"janus":sys.modules[__name__]})
    try:
        import readline
        import rlcompleter
        readline.set_completer(rlcompleter.Completer(vars).complete)
        readline.parse_and_bind("tab: complete")
    except:
        pass
    try:
        code.InteractiveConsole(vars).interact()
    except SystemExit:          # quit() throws SystemExit
        print("now exiting InteractiveConsole...")

def prolog():
    """
    Start and interactive Prolog toplevel.
    """
    query_once("'$toplevel':setup_interactive")
    query_once("prolog")

import sys, importlib.util

# from https://stackoverflow.com/a/53080237/717069
def import_module_from_string(name: str, source: str):
    """
    Import module from source string.
    Example use:
    import_module_from_string("m", "f = lambda: print('hello')")
    m.f()
    """
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(source, module.__dict__)
    sys.modules[name] = module
    globals()[name] = module

################################################################
# Emulated XSB interface

"cmd = _swipl."

def comp(module, pred, *args, vars=1, set_collect=False, truth_vals=TruthVal.PLAIN_TRUTHVALS):
    """Call non-deterministic predicate


    Examples
    --------

    >>> comp("user", "between", 1, 6)
    [((1,), 1), ((2,), 1), ((3,), 1), ((4,), 1), ((5,), 1), ((6,), 1)]

    Parameters
    ----------
    vars : int=1
        Number of "output" variables that appear after `args`.
    set_collect : Bool=False
        When True, return a _set_ of answers rather than a _list_.
    truth_vals : (PLAIN_TRUTHVALS|DELAY_LISTS|NO_TRUTHVALS)=PLAIN_TRUTHVALS
        When `NO_TRUTHVALS`, answers are no tuples.  Otherwise each answer
        is a tuple `(Value,Truth)`.  Using `PLAIN_TRUTHVALS`, Truth is
        one of 1 or 2 (undefined).  Using `DELAY_LISTS`, the delay list
        as returned by call_delays/2 is returned.

    Returns
    -------
    answers: list
        Each answer is a either a tuple holding the converted values
        for each of the output arguments or a tuple holding this tuple
        and the truth value.

    """
    d = query_once("janus:px_comp(M,P,Args,Vars,Set,TV,Ret)",
             { "M":module,
               "P":pred,
               "Args":args,
               "Vars":vars,
               "Set":set_collect,
               "TV":truth_vals
              })
    return d["Ret"]

################################################################
# Represent Prolog data

class Term:
    """Represent any Prolog term

    Class `Term` is much like the Python object reference that we have
    in Prolog: it represents an arbitrary Prolog term we cannot represent
    in Python.  Instances are created if data is passed to Python as
    `prolog(Term)`.  Upon transforming the data back to Prolog, the
    interface recovers a copy of the original Prolog terms.

    The user should never create instances of this explicitly.
    """

    def __init__(self, record):
        """Create from a Prolog record pointer. DO NOT USE!"""
        self._record = record;
    def __str__(self):
        """Return the output of print/1 on self"""
        return query_once("with_output_to(string(Str),print(Msg))",
                    {"Msg":self})["Str"]
    def __repr__(self):
        """Return the output of write_canonical/1 on self"""
        return query_once("with_output_to(string(Str),write_canonical(Msg))",
                    {"Msg":self})["Str"]
    def __del__(self):
        """Destroy the represented term"""
        record = self._record;
        self.record = 0
        _swipl.erase(record)

class PrologError(Exception):
    """Represent a Prolog exception

    This class is used when calling Prolog from Python to represent that
    an exception occurred.  If the error comes from Prolog itself, it is
    represented as a Prolog term.  If it originates from illegal use of
    the Python interface functions before Prolog is called, it is
    represented as a string.

    Attributes
    ----------
    term: Term|None
        An instance of class `Term` that represents the exception.
    message: str|None
        Exception from a string
    """
    def __init__(self, msg):
        """Create an instance from a Term or str"""
        if ( isinstance(msg, Term) ):
            self.term = msg
            self.message = None
        else:
            self.message = msg
            self.term = None
    def __str__(self):
        """Return the output of message_to_string/2 on the term"""
        if ( self.term ):
            return query_once("message_to_string(Msg,Str)", {"Msg":self.term})["Str"]
        else:
            return self.message
    def __repr__(self):
        """Return the output of write_canonical/1 on term"""
        if ( self.term ):
            return query_once("with_output_to(string(Str),write_canonical(Msg))",
                         {"Msg":self.term})["Str"]
        else:
            return self.message


################################################################
# Rebind I/O

import io
import sys

# `prompt` is  the current prompt  that we  get using the  audit event
# `builtins.input`.  This is then written  to `stdout`.  We don't want
# that because the Prolog command  line editor writes the prompt.  So,
# the next write to `stdout` that writes the prompt is ignored.
#
# Hopefully there is a cleaner way to achieve this.

prompt=""
ignore=None

class PrologIO(io.TextIOWrapper):
    """Redefine terminal I/O

    Subclass `io.TextIOWrapper`, refining the I/O methods to call Prolog.
    `sys.stdin`, etc., are set to instances of this class such that console
    I/O of Python uses Prolog's console I/O and we can use e.g. py_shell/0
    also from `swipl-win` or other environments that redirect Prolog's
    console to something else that the POSIX file descriptors 0,1 and 2.
    """
    def __init__(self, plstream, *args, **kwargs):
        self.prolog_stream = plstream
        super().__init__: callable(args, kwargs)
    def write(self, s):
        global ignore
        if ( ignore and ignore == s and self.prolog_stream == "user_output" ):
            ignore = None
        else:
            query_once("janus:py_write(Stream, String)",
                 {'Stream':self.prolog_stream, 'String':s})
    def readline(self, size=-1):
        global prompt
        return query_once("janus:py_readline(Stream, Size, Prompt, Line)",
                    {'Stream':self.prolog_stream, 'Size':size, 'Prompt':prompt})['Line']

def audit(event, args):
    """Intercept the current prompt"""
    if ( event == "builtins.input" ):
        global prompt
        prompt = args[0];
        global ignore
        ignore = args[0];

def connect_io(stdin=True, stdout=True, stderr=True):
    """Handle Python console I/o using Prolog's I/O primitives
    """
    if ( stdin ):
        sys.stdin  = PrologIO("user_input",  io.BytesIO(), line_buffering=True)
        sys.addaudithook(audit)
    if ( stdout ):
        sys.stdout = PrologIO("user_output", io.BytesIO(), line_buffering=True)
    if ( stderr ):
        sys.stderr = PrologIO("user_error",  io.BytesIO(), write_through=True)
import os
import sys
import subprocess
import re

def swipl_properties():
    try:
        return swipl_exe_properties()
    except:
        exe = find_swipl()
        if ( exe ):
            return swipl_exe_properties(find_swipl())
        return None
    
def swipl_exe_properties(exe="swipl"):
    config = subprocess.run([exe, '--dump-runtime-variables'],
                            stdout=subprocess.PIPE).stdout.decode('utf-8')
    props = {}
    for line in config.splitlines():
        i = line.find("=")      # line is name="value";
        name = line[0:i]
        value = line[i+2:-2]
        props[name] = value;
    return props

def find_swipl():
    if ( sys.platform == "win32" ):
        home = _win32_home_from_registry()
        if ( home ):
            return os.path.join(home, "bin", "swipl.exe")
    return None

def _win32_home_from_registry():
    reg = subprocess.run(["reg", 'query',
                          r'HKEY_LOCAL_MACHINE\Software\SWI\Prolog',
                          '/v', 'home'],
                         stdout=subprocess.PIPE).stdout.decode('utf-8')
    for line in reg.splitlines():
        match = re.match(r"\s*home\s+REG_SZ\s+(.*)$", line)
        if ( match ):
            return match.group(1)
    return None
# Copyright 2023 Theresa Swift and Carl Anderson
#
# Permission is hereby granted, free of charge,  to any person obtaining a
# copy  of  this  software  and    associated   documentation  files  (the
# “Software”), to deal in  the   Software  without  restriction, including
# without limitation the rights to  use,   copy,  modify,  merge, publish,
# distribute, sublicense, and/or sell  copies  of   the  Software,  and to
# permit persons to whom the Software is   furnished  to do so, subject to
# the following conditions:
#
# The above copyright notice and this  permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT  WARRANTY OF ANY KIND, EXPRESS
# OR  IMPLIED,  INCLUDING  BUT  NOT   LIMITED    TO   THE   WARRANTIES  OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR   PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS  OR   COPYRIGHT  HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY,  WHETHER   IN  AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM,  OUT  OF   OR  IN  CONNECTION  WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

def sumlist3(X,Y):
#	print('First element to combine with is '+str(X))
	Z = []
	for element in Y:
		Z.append(X+element)
	return Z
# Copyright 2023 Theresa Swift and Carl Anderson
#
# Permission is hereby granted, free of charge,  to any person obtaining a
# copy  of  this  software  and    associated   documentation  files  (the
# “Software”), to deal in  the   Software  without  restriction, including
# without limitation the rights to  use,   copy,  modify,  merge, publish,
# distribute, sublicense, and/or sell  copies  of   the  Software,  and to
# permit persons to whom the Software is   furnished  to do so, subject to
# the following conditions:
#
# The above copyright notice and this  permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT  WARRANTY OF ANY KIND, EXPRESS
# OR  IMPLIED,  INCLUDING  BUT  NOT   LIMITED    TO   THE   WARRANTIES  OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR   PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS  OR   COPYRIGHT  HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY,  WHETHER   IN  AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM,  OUT  OF   OR  IN  CONNECTION  WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json

def prolog_loads(String):
    jdict = json.loads(String)
    return(jdict)

def prolog_load(File):
    with open(File) as fileptr:
        data = json.load(fileptr)
        return(data)

#should not be needed -- transformation now done in C.
def dict_to_list(indict):
    originally_dict = False
    orig_struct = indict
    if type(indict) not in [dict,list,tuple]:
        return indict
    elif type(indict) is dict:
        indict = list(indict.items())
        originally_dict = True
    retstruct = []
    print("  ",end = " ")
    print(indict)
    for elt in indict:
        if type(elt) in [dict,list,tuple]:
            newelt = dict_to_list(elt)
        else:
            newelt = elt
        retstruct.append(newelt)
    if type(indict) is tuple:
        retstruct = tuple(retstruct)
    elif originally_dict == True:
        retstruct = ("__dict",retstruct)
    return(retstruct)

# Output: {'name': 'Bob', 'languages': ['English', 'Fench']}

def prolog_dumps(list):
    jdict = json.loads(String)
    jlist = list(jdict.items())
    return(jlist)


# Copyright 2023 Theresa Swift and Carl Anderson
#
# Permission is hereby granted, free of charge,  to any person obtaining a
# copy  of  this  software  and    associated   documentation  files  (the
# “Software”), to deal in  the   Software  without  restriction, including
# without limitation the rights to  use,   copy,  modify,  merge, publish,
# distribute, sublicense, and/or sell  copies  of   the  Software,  and to
# permit persons to whom the Software is   furnished  to do so, subject to
# the following conditions:
#
# The above copyright notice and this  permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT  WARRANTY OF ANY KIND, EXPRESS
# OR  IMPLIED,  INCLUDING  BUT  NOT   LIMITED    TO   THE   WARRANTIES  OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR   PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS  OR   COPYRIGHT  HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY,  WHETHER   IN  AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM,  OUT  OF   OR  IN  CONNECTION  WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

def kwargs_append(X,**Features):
    List = [X]
    for (key,value) in Features.items():
        List.append((key,value))
    return(List)


# Copyright 2023 Theresa Swift and Carl Anderson
#
# Permission is hereby granted, free of charge,  to any person obtaining a
# copy  of  this  software  and    associated   documentation  files  (the
# “Software”), to deal in  the   Software  without  restriction, including
# without limitation the rights to  use,   copy,  modify,  merge, publish,
# distribute, sublicense, and/or sell  copies  of   the  Software,  and to
# permit persons to whom the Software is   furnished  to do so, subject to
# the following conditions:
#
# The above copyright notice and this  permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT  WARRANTY OF ANY KIND, EXPRESS
# OR  IMPLIED,  INCLUDING  BUT  NOT   LIMITED    TO   THE   WARRANTIES  OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR   PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS  OR   COPYRIGHT  HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY,  WHETHER   IN  AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM,  OUT  OF   OR  IN  CONNECTION  WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import numpy as np

mat = np.arange(15).reshape(3, 5)

def go():
    dim = np.ndim(mat)
    return(dim)

