import os
import sqlite3
import subprocess

# --- Nepal SBOM Scanner Demonstration File ---
# This file contains intentionally vulnerable code and hardcoded secrets
# to demonstrate the capabilities of the Nepal SBOM Scanner's source code analysis.
# DO NOT USE THIS CODE IN PRODUCTION!

class VulnerableApp:
    def __init__(self):
        # 1. Hardcoded AWS Credentials (High Severity)
        self.aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
        self.aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        # 2. Hardcoded Database Credentials in URL (High Severity)
        self.db_url = "postgres://admin:SuperSecret123@db.example.com:5432/production"
        
        # 3. Hardcoded API Token (High Severity)
        self.github_token = "ghp_1234567890abcdefghijklmnopqrstuvwx"

    def connect_db(self):
        # Vulnerable pattern: connecting with hardcoded credentials
        print(f"Connecting to {self.db_url}...")
        # ... connection logic ...

    def execute_user_command(self, user_input):
        # 4. Command Injection Vulnerability (Critical Severity)
        # Directly using user input in a shell command is extremely dangerous
        print(f"Executing: ping -c 1 {user_input}")
        # Pattern match: os.system or subprocess with shell=True
        os.system("ping -c 1 " + user_input)

    def load_user_profile(self, serialized_data):
        import pickle
        # 5. Insecure Deserialization (Critical Severity)
        # Unpickling untrusted data can lead to arbitrary code execution
        print("Loading profile data...")
        # Pattern match: pickle.load
        profile = pickle.loads(serialized_data)
        return profile

    def process_xml(self, xml_string):
        import xml.etree.ElementTree as ET
        # Additional vulnerability context (often flagged by advanced SAST)
        # Python's default xml parser is vulnerable to XXE (XML External Entity) attacks
        root = ET.fromstring(xml_string)
        return root

if __name__ == "__main__":
    app = VulnerableApp()
    app.connect_db()
    # In a real app, user_input would come from a web request
    app.execute_user_command("127.0.0.1; rm -rf /") 
