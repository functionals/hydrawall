# -*- coding: utf-8 -*-


"""
Created on Wed Aug 14 15:23:13 2024

@author: Ian Malloy
"""

"prolog buffer output to hydrawall"
"run all prolog buffers"


# -*- coding: utf-8 -*-
#!/usr/bin/python3
import os
import sys
import queue
import threading
import argparse
from subprocess import Popen, PIPE
import venv
import asyncio
import heapq


# Define the worker function for threading
def worker(sync_q):
    while True:
        item = sync_q.get()
        if item is None:  # Sentinel value to stop the worker
            break
        print(f"Processed item: {item}")
        sync_q.task_done()  # Notify that a task has been completed

def threaded(sync_q):
    # Populate the queue with items
    for i in range(100):
        sync_q.put(i)

    # Start worker thread
    worker_thread = threading.Thread(target=worker, args=(sync_q,))
    worker_thread.start()

    # Wait for all tasks to be processed
    sync_q.join()

    # Stop the worker
    sync_q.put(None)  # Sending sentinel value to stop the worker
    worker_thread.join()

# Asynchronous Queue Processing
async def produce(Q, n_jobs):
    for i in range(n_jobs):
        await Q.put(i)
        await asyncio.sleep(0.1)

async def consume(Q, heap):
    while True:
        item = await Q.get()
        if item is None:
            break
        print(f"Consumed: {item}")
        heapq.heapreplace(heap, item)

async def async_main():
    Q = asyncio.Queue()
    heap = [0]
    producer_task = asyncio.create_task(produce(Q, 10))
    consumer_task = asyncio.create_task(consume(Q, heap))

    await producer_task
    await Q.put(None)
    await consumer_task

    print(f"Final heap: {heap}")

# Command-line argument parsing and virtual environment setup
class ExtendedEnvBuilder(venv.EnvBuilder):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.nodist = kwargs.get('nodist', False)
        self.nopip = kwargs.get('nopip', False)
        self.verbose = kwargs.get('verbose', False)

def main_venv():
    parser = argparse.ArgumentParser(description='Create virtual Python environments.')
    parser.add_argument('dirs', metavar='ENV_DIR', nargs='+', help='Directory to create the virtual environment in.')
    parser.add_argument('--no-setuptools', default=False, action='store_true', dest='nodist', help="Don't install setuptools or pip.")
    parser.add_argument('--no-pip', default=False, action='store_true', dest='nopip', help="Don't install pip.")
    parser.add_argument('--system-site-packages', default=False, action='store_true', dest='system_site', help='Access to system site-packages.')
    parser.add_argument('--symlinks', default=os.name != 'nt', action='store_true', dest='symlinks', help='Use symlinks rather than copies.')
    parser.add_argument('--clear', default=False, action='store_true', dest='clear', help='Clear existing contents of the environment directory.')
    parser.add_argument('--upgrade', default=False, action='store_true', dest='upgrade', help='Upgrade the virtual environment.')
    parser.add_argument('--verbose', default=False, action='store_true', dest='verbose', help='Verbose output.')
    options = parser.parse_args()

    if not options.dirs:
        parser.error("At least one ENV_DIR argument is required.")
    if options.upgrade and options.clear:
        raise ValueError('Cannot supply --upgrade and --clear together.')

    builder = ExtendedEnvBuilder(system_site_packages=options.system_site, clear=options.clear,
                                symlinks=options.symlinks, upgrade=options.upgrade,
                                nodist=options.nodist, nopip=options.nopip, verbose=options.verbose)
    for d in options.dirs:
        builder.create(d)

# Function to send commands to SWI-Prolog and import output into a class
class PrologHandler:
    def __init__(self, prolog_path='swipl'):
        self.prolog_path = prolog_path

    def send_command(self, command):
        try:
            process = Popen([self.prolog_path, '-q'], stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = process.communicate(command)
            if process.returncode == 0:
                return stdout
            else:
                raise RuntimeError(f"Prolog Error: {stderr}")
        except Exception as e:
            raise RuntimeError(f"Failed to execute Prolog command: {e}")

# Example usage of PrologHandler
def main_prolog():
    prolog_handler = PrologHandler()
    result = prolog_handler.send_command("?- write('Hello, Prolog!'), nl.")
    print("Prolog Output:", result)

# Run the appropriate function based on command-line arguments
def run_main():
    if len(sys.argv) > 1 and sys.argv[1] in ['venv', 'prolog']:
        if sys.argv[1] == 'venv':
            main_venv()
        elif sys.argv[1] == 'prolog':
            main_prolog()
    else:
        if asyncio.get_event_loop().is_running():
            # If an event loop is already running, we should use the existing loop
            asyncio.ensure_future(async_main())
        else:
            # No event loop running, use asyncio.run
            asyncio.run(async_main())
        # Example call to threaded function
        sync_q = queue.Queue()
        threaded(sync_q)

if __name__ == '__main__':
    run_main()
