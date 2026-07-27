########UPDATE SMART BETA

# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 12:38:01 2024

@author: Ian Malloy
"""

##########################TODO
#       SET TF AS A SERVER FOR DDE
#
#   Byte Strings for subprocess module
#     between Dshell and tf, 
#    tf and smart, 
#     and Dshell/smart
#
#
# Hydrawall inputs to recursive functions in smart, sampling from succesful values
#   as prime nodes in a lattice of tf output
#
#
#   Dshell socket to tf in sockets,
#   smart to tf as tf dde server,
#   tf to smart in dde
#   dshell socket to hydrawall
#   commands from hydra to smart and smart out to hydra and terminal
# map heapq to prime nodes and set iterations 
# of tensor flow to bfs iterations.
#
# put subprocess, asyncio, and heapq in dhsell,
# passing to tensorflow and hydrawall
#   Write Primality test in python
#   Rewrite Primality test in SWI-Prolog
###################################

import tempfile
import win32ui
import dde
import win32com.client
import heapq
import asyncio
import subprocess
import logging
from optparse import OptionParser
from config import Config


with tempfile.TemporaryFile() as tempf:
    proc = subprocess.Popen(['echo', 'a', 'b'], stdout=tempf)
    proc.wait()
    tempf.seek(0)
    print(tempf.read())

class PrologHandler:
    def __init__(self, config):
        self.prolog_path = config.get_prolog_path()
    
    def send_command(self, command):
        """Send a command to SWI-Prolog and return the output."""
        try:
            process = subprocess.Popen(
                [self.prolog_path, '-q'],  # Run SWI-Prolog in quiet mode
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(command)
            if process.returncode == 0:
                return stdout
            else:
                raise RuntimeError(f"Prolog Error: {stderr}")
        except Exception as e:
            raise RuntimeError(f"Failed to execute Prolog command: {e}")

def run_prolog_command(prolog_script, command):
    """
    Run a Prolog command by calling a Prolog script using subprocess.
    :param prolog_script: Path to the Prolog script.
    :param command: The Prolog command or query to execute.
    :return: The output of the Prolog command.
    """
    prolog_command = ['swipl', prolog_script, '-g', command, '-t', 'halt']
    
    try:
        result = subprocess.run(prolog_command, capture_output=True, text=True)
        if result.returncode == 0:
            print("Prolog Output:", result.stdout)
        else:
            print("Prolog Error:", result.stderr)
    except Exception as e:
        print(f"Failed to run Prolog command: {e}")



def main():
    with open('output.txt', 'r') as file:
        binary_string = file.read().strip()

    
if __name__ == "__main__":
    main()


def send_dde_command(command):
    server = win32ui.CreateDdeServer()
    server.Create('hydrawall', 'smart', 'tf')
    server.Start()
    
    dde_client = win32com.client.Dispatch('WinDDEClient.DDE')
    dde_client.Poke('smart', command)

server = dde.CreateServer()
server.Create("update")
conversation = dde.CreateConversation(server)
conversation.ConnectTo("tf.py","Anything")
conversation.ConnectTo("smart.pl","Anything")

def receive_dde_data():
    dde_server = win32ui.CreateDdeServer()
    dde_server.Create('hydrawall', 'smart')
    dde_server.Start()
    
    while True:
        try:
            data = dde_server.Receive()
            print(f"Received data from Prolog: {data}")
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    
    send_dde_command('start.')
    
    # Start receiving data
    receive_dde_data()

def write_string_to_file(filename, string):
    """Write a string to a file."""
    try:
        with open(filename, 'w') as file:
            file.write(string + '\n')
    except Exception as e:
        print(f"Failed to write to file: {e}")

def run_prolog_script(prolog_script):
    """Run a Prolog script and print its output."""
    try:
        result = subprocess.run(['swipl', prolog_script], capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Error:", result.stderr)
    except Exception as e:
        print(f"Failed to run Prolog script: {e}")

def parse_args():
    """Parse command-line arguments."""
    parser = OptionParser()
    parser.add_option("-c", "--command", dest="command",
                      help="Command to send to SWI-Prolog", metavar="COMMAND")
    parser.add_option("-p", "--prolog", dest="prolog_path", default='swipl',
                      help="Path to SWI-Prolog executable", metavar="PROLOG_PATH")
    return parser.parse_args()

class Smart:
    def smart_method(self):
        print("Executing smart")

    def janus_swi(self):
        print("Executing janus")

    @staticmethod
    def smart_static_method():
        print("Executing smart_static")

class KnowledgeBase:
    def __init__(self):
        self.facts = {}
        self.rules = {}

    def assert_fact(self, fact):
        self.facts[fact] = True

    def define_rule(self, rule_name, rule_body):
        self.rules[rule_name] = rule_body

    def process_input(self, input_str):
        if ':-' in input_str:
            head, body = input_str.split(':-')
            self.define_rule(head.strip(), body.strip())
        else:
            self.assert_fact(input_str.strip())

    def smart(self):
        while True:
            input_str = input("Enter query: ")
            if input_str.lower() == 'exit':
                break
            self.process_input(input_str)

def heapreplace(heap, item):
    """Replace the smallest item with a new item in the heap."""
    if item > heap[0]:
        heapq.heapreplace(heap, item)
    return heap

def heappush(heap, item):
    """Push a new item onto the heap."""
    heapq.heappush(heap, item)

def heappop(heap):
    """Pop the smallest item off the heap."""
    return heapq.heappop(heap)

def heapify(heap):
    """Transform a list into a heap."""
    heapq.heapify(heap)

def merge(*iterables, key=None, reverse=False):
    """Merge multiple sorted iterables into a single sorted iterable."""
    if reverse:
        _heapify = heapq._heapify_max
        _heappop = heapq._heappop_max
        _heapreplace = heapq._heapreplace_max
        direction = -1
    else:
        _heapify = heapq.heapify
        _heappop = heapq.heappop
        _heapreplace = heapq.heapreplace
        direction = 1

    h = []
    for order, it in enumerate(map(iter, iterables)):
        try:
            next_item = it.__next__
            h.append([next_item(), order * direction, next_item])
        except StopIteration:
            pass
    _heapify(h)
    while len(h) > 1:
        try:
            while True:
                value, order, next_item = h[0]
                yield value
                s = h[0]
                s[0] = next_item()
                _heapreplace(h, s)
        except StopIteration:
            _heappop(h)
    if h:
        value, order, next_item = h[0]
        yield value
        yield from next_item.__self__

def nsmallest(n, iterable, key=None):
    """Find the n smallest elements in an iterable."""
    if n == 1:
        it = iter(iterable)
        sentinel = object()
        result = min(it, default=sentinel, key=key)
        return [] if result is sentinel else [result]

    try:
        size = len(iterable)
    except (TypeError, AttributeError):
        pass
    else:
        if n >= size:
            return sorted(iterable, key=key)[:n]

    if key is None:
        it = iter(iterable)
        result = [(elem, i) for i, elem in zip(range(n), it)]
        if not result:
            return result
        heapify(result)
        top = result[0][0]
        order = n
        for elem in it:
            if elem < top:
                heapreplace(result, (elem, order))
                top, _order = result[0]
                order += 1
        result.sort()
        return [elem for elem, _order in result]

    it = iter(iterable)
    result = [(key(elem), i, elem) for i, elem in zip(range(n), it)]
    if not result:
        return result
    heapify(result)
    top = result[0][0]
    order = n
    for elem in it:
        k = key(elem)
        if k < top:
            heapreplace(result, (k, order, elem))
            top, _order, _elem = result[0]
            order += 1
    result.sort()
    return [elem for k, _order, elem in result]

def write_stream_to_file(file_path, stream_data):
    """
    Write the given stream data to an extensionless file.

    :param file_path: The path to the extensionless file.
    :param stream_data: The data stream to write to the file.
    """
    try:
        with open(file_path, 'w') as file:
            file.write(stream_data)
        print(f"Data successfully written to {file_path}")
    except Exception as e:
        print(f"Failed to write to file: {e}")

if __name__ == "__main__":
    options, _ = parse_args()
    if options.command:
        prolog_handler = PrologHandler(Config())
        prolog_handler.send_command(options.command)
    else:
        print("No command specified. Use -c option to provide a Prolog command.")

    # Example usage of PrologHandler
    config = Config()
    logging.basicConfig(level=config.get_python_logging_level())
    prolog_handler = PrologHandler(config)
    prolog_command = config.get_prolog_command()
    result = prolog_handler.send_command(prolog_command)
    print("Prolog Output:", result)

    # Example usage of Smart class
    smart_instance = Smart()
    smart_instance.smart_method()
    smart_instance.janus_swi()
    smart_instance.smart_static_method()

    # Example usage of KnowledgeBase class
    kb = KnowledgeBase()
    kb.smart()

    # Example file operations
    filename = 'output.txt'
    prolog_script = 'smart.pl'
    string_to_pass = ':-start, main.'
    
    write_string_to_file(filename, string_to_pass)
    run_prolog_script(prolog_script)
    
    # Example stream data write
    file_path = 'data'
    stream_data = "This is some example content for the extensionless file."
    write_stream_to_file(file_path, stream_data)

    # Example heap operations
    async def produce(queue, n_jobs):
        for i in range(n_jobs):
            await queue.put(i)
            await asyncio.sleep()



def call_prolog_script(command):
    script_path = '/hydrawall/smart.pl'
    try:
        result = subprocess.run(['python', script_path, command], capture_output=True, text=True)
        print("Script Output:", result.stdout)
        if result.stderr:
            print("Script Error:", result.stderr)
    except Exception as e:
        print(f"Failed to call script: {e}")

if __name__ == "__main__":
    command = "smart:input(dshell.py)"
    call_prolog_script(command)

def dshell(command):
    script_path = '/hydrawall/dshell'
    try:
        result = subprocess.run(['python', script_path, command], capture_output=True, text=True)
        print("Script Output:", result.stdout)
        if result.stderr:
            print("Script Error:", result.stderr)
    except Exception as e:
        print(f"Failed to call script: {e}")

if __name__ == "dshell":
    command = "dshell command:"
    dshell(command)


"""
Modified Tue Aug 20 20:08:13 2024 to fit Hydrawall: Ian Malloy, 2024
"""
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




import janus

jpy = janus  # Default to janus as jpy

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
  
################################################################
# Misc functions

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
    jdict = json.loads(smart_instance)
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