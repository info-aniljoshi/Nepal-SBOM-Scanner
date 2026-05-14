"""
Intentionally vulnerable patterns for SAST demos and scanner regression tests.
Do not import this module in production applications.
"""
import os
import yaml

user_input = input("Enter command: ")
os.system("ls " + user_input)  # Dangerous: command injection

data = yaml.load(open("config.yaml"))  # Dangerous: use yaml.safe_load
