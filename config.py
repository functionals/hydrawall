# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 22:31:34 2024

@author: M
"""
import logging
import os

class Config:
    def __init__(self):
        # Load configuration from environment variables or set default values
        self.prolog_path = os.getenv('PROLOG_PATH', 'swipl')
        self.python_logging_level = os.getenv('PYTHON_LOGGING_LEVEL', 'INFO').upper()
        self.prolog_command = os.getenv('PROLOG_COMMAND', "?- write('Hello, Prolog!'), nl.")
    
    def get_prolog_path(self):
        return self.prolog_path
    
    def get_python_logging_level(self):
        return getattr(logging, self.python_logging_level, logging.INFO)
    
    def get_prolog_command(self):
        return self.prolog_command
