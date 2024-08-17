# -*- coding: utf-8 -*-

"""
Created on Thu Aug 15 22:34:31 2024
@author: Ian Malloy
"""

"""
Created on Thu Aug 15 22:34:31 2024
@author: Ian Malloy
"""
import heapq
import asyncio
import logging
from optparse import OptionParser

class Config:
    """Configuration class for managing settings."""

    def __init__(self):
        self.prolog_path = 'swipl'
        self.python_logging_level = logging.INFO
        self.prolog_command = 'your_prolog_command_here'
    
    def get_prolog_path(self):
        return self.prolog_path

    def get_python_logging_level(self):
        return self.python_logging_level

    def get_prolog_command(self):
        return self.prolog_command

class SubprocessHandler:
    """Class to handle subprocess commands with priority."""

    def __init__(self):
        self.task_queue = []
        self.USER_INPUT_PRIORITY = 1
        self.FILE_OPERATION_PRIORITY = 2

    def add_task(self, priority, func):
        """Add a task to the queue with a given priority."""
        heapq.heappush(self.task_queue, (priority, func))

    async def run(self):
        """Process tasks from the queue."""
        while self.task_queue:
            priority, task = heapq.heappop(self.task_queue)
            if callable(task):
                await task()  # Execute the task

    async def run_command(self, command):
        """Run a command using subprocess and manage its output and errors."""
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            text=True
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return stdout
        else:
            raise RuntimeError(f"Command Error: {stderr}")

    async def handle_command(self, command):
        """Run the command and send output to a script."""
        output = await self.run_command(command)
        await self.write_output_to_file('hydrawall.py', output)

    async def write_output_to_file(self, filename, output):
        """Write output to a Python script."""
        try:
            with open(filename, 'a') as file:
                file.write(output + '\n')
        except Exception as e:
            print(f"Failed to write to file: {e}")

class PrologHandler:
    def __init__(self, config):
        self.prolog_path = config.get_prolog_path()
        self.subprocess_handler = SubprocessHandler()
    
    async def send_command(self, command):
        """Send a command to SWI-Prolog and handle its output."""
        prolog_command = [self.prolog_path, '-q', '-c', command]
        await self.subprocess_handler.handle_command(prolog_command)

async def run_prolog_command(prolog_script, command):
    """Run a Prolog command by calling a Prolog script."""
    prolog_command = ['swipl', prolog_script, '-g', command, '-t', 'halt']
    subprocess_handler = SubprocessHandler()
    await subprocess_handler.handle_command(prolog_command)

def write_string_to_file(filename, string):
    """Write a string to a file synchronously."""
    try:
        with open(filename, 'w') as file:
            file.write(string + '\n')
    except Exception as e:
        print(f"Failed to write to file: {e}")

async def run_prolog_script(prolog_script):
    """Run a Prolog script and write its output to a file."""
    prolog_command = ['swipl', prolog_script]
    subprocess_handler = SubprocessHandler()
    await subprocess_handler.handle_command(prolog_command)

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

    async def smart(self):
        while True:
            input_str = input("Enter definition as predication: ")
            if input_str.lower() == 'exit':
                break
            self.process_input(input_str)

async def main():
    options, _ = parse_args()
    config = Config()
    logging.basicConfig(level=config.get_python_logging_level())

    prolog_handler = PrologHandler(config)
    subprocess_handler = SubprocessHandler()

    if options.command:
        subprocess_handler.add_task(subprocess_handler.FILE_OPERATION_PRIORITY, lambda: prolog_handler.send_command(options.command))

    # Example usage of Smart class
    smart_instance = Smart()
    subprocess_handler.add_task(subprocess_handler.USER_INPUT_PRIORITY, smart_instance.smart_method)

    # Example usage of KnowledgeBase class
    kb = KnowledgeBase()
    subprocess_handler.add_task(subprocess_handler.USER_INPUT_PRIORITY, kb.smart)

    # File operations
    filename = 'input.txt'
    prolog_script = 'prolog_script.pl'
    string_to_pass = 'Hello from Python!'
    
    subprocess_handler.add_task(subprocess_handler.FILE_OPERATION_PRIORITY, lambda: write_string_to_file(filename, string_to_pass))
    subprocess_handler.add_task(subprocess_handler.FILE_OPERATION_PRIORITY, lambda: run_prolog_script(prolog_script))
    
    # Process tasks from the queue
    await subprocess_handler.run()

if __name__ == "__main__":
    try:
        # Check if there is already an event loop running
        loop = asyncio.get_event_loop()
        if loop.is_running():
            print("Event loop is already running. Use await for async operations.")
        else:
            asyncio.run(main())
    except RuntimeError as e:
        print(f"RuntimeError: {e}")
