# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 22:34:31 2024

@author: M
"""

import subprocess
import logging
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

def main():
    # Load configuration
    config = Config()
    
    # Set up logging
    logging.basicConfig(level=config.get_python_logging_level())
    
    # Initialize Prolog handler
    prolog_handler = PrologHandler(config)
    
    # Execute Prolog command
    prolog_command = config.get_prolog_command()
    result = prolog_handler.send_command(prolog_command)
    
    print("Prolog Output:", result)

if __name__ == '__main__':
    main()
