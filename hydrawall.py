########UPDATE 20

# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 12:38:01 2024

@author: Ian Malloy
"""

##########################TODO
#
#
#   Byte Strings for subprocess module
#     between Dshell and tf, 
#    tf and smart, 
#     and Dshell/smart
#
#
# map heapq to prime nodes and set iterations 
# of tensor flow to bfs iterations.
#
# put subprocess, asyncio, and heapq in dhsell,
# passing to tensorflow and hydrawall
#   Write Primality test in python
#   Rewrite Primality test in SWI-Prolog
###################################


import win32ui
import win32com.client
import heapq
import asyncio
import subprocess
import logging
from optparse import OptionParser
from config import Config

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
    server.Create('PythonApp', 'PrologApp')
    server.Start()
    
    dde_client = win32com.client.Dispatch('WinDDEClient.DDE')
    dde_client.Poke('PrologApp', command)

def receive_dde_data():
    dde_server = win32ui.CreateDdeServer()
    dde_server.Create('PythonApp', 'PrologApp')
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
        print("Executing smart_method")

    def janus_swi(self):
        print("Executing janus_swi")

    @staticmethod
    def smart_static_method():
        print("Executing smart_static_method")

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
    filename = 'input.txt'
    prolog_script = 'prolog_script.pl'
    string_to_pass = 'Hello from Python!'
    
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
    script_path = '/hydrawall/lib_dir/lib_pl/swip.py'
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
