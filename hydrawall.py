# -*- coding: utf-8 -*-
"""
Created on Thu Aug 15 12:38:01 2024

@author: Ian Malloy
"""
# swip.py
import subprocess

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
    command = "your_prolog_command_here"
    call_prolog_script(command)

def dshell(command):
    script_path = '/hydrawall/lib_dir/lib_py/dshell'
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
