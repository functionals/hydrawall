# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 21:26:36 2024

@author: Ian Malloy
"""

import yaml
import logging

class Config:
    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """ Load and parse the YAML configuration file. """
        with open(self.config_file, 'r') as file:
            return yaml.safe_load(file)
    
    def get_prolog_path(self):
        """ Get the Prolog executable path. """
        return self.config.get('prolog', {}).get('path', 'swipl')

    def get_prolog_command(self):
        """ Get the default Prolog command. """
        return self.config.get('prolog', {}).get('command', "")

    def get_python_logging_level(self):
        """ Get the logging level for Python. """
        level = self.config.get('python', {}).get('logging', {}).get('level', 'INFO')
        return getattr(logging, level.upper(), logging.INFO)

    def get_database_config(self):
        """ Get the database configuration. """
        return self.config.get('python', {}).get('database', {})

# Example usage:
if __name__ == '__main__':
    config = Config()
    print("Prolog Path:", config.get_prolog_path())
    print("Prolog Command:", config.get_prolog_command())
    print("Logging Level:", config.get_python_logging_level())
    print("Database Config:", config.get_database_config())
