# Project: Project Diamond - APP2
# Purpose Details: Receive a secure JSON payload from APP1 over TLS,
#                  save it to a file, and log pass/fail events to Eve/MongoDB.
# Course: HCDD 411
# Author: Kelly Rawlings, De'Von Williams
# Due Date: 12 October, 2025
# Date Developed: 10/09/2025
# Last Date Changed: 10/09/2025
# Rev: 1

"""
Project: Project Diamond - APP2
Course: HCDD 411
Authors: Kelly Rawlings, De'Von Williams
Due Date: 12 October, 2025

App2 TLS Receiver and Forwarder
--------------------------------
This module implements the secure middle component (APP2) of Project Diamond.
It performs the following operations:

1. Accepts incoming TLS connections from APP1 on a configured host/port.
2. Receives a JSON payload sent over the TLS session.
3. Logs activity to an Eve/MongoDB REST API using simple urllib POSTs.
4. Saves the received payload to disk as 'received_payload.json'.
5. Generates an HMAC-SHA256 signature for the payload using a shared secret key.
6. Forwards the payload + HMAC to APP3 via SFTP (secure copy over SSH).

This module can be documented with:
    pydoc3 -wApp2
"""

import os
import json
import socket
import ssl
import traceback
from datetime import datetime
from urllib import request as urlrequest
from urllib.error import URLError
import hashlib, hmac
import pysftp, getpass

# ------------------ configurable ------------------
HOST = "127.0.0.1"
PORT = 8080
CERT_FILE = "server.crt"
KEY_FILE = "server.key"
OUTPUT_FILE = "received_payload.json"
HASH_KEY = os.environ["DIAMOND_HMAC_KEY"]

# Eve REST endpoint for activity logs (your teammates run Eve on 5000)
# override with ENV if needed, e.g., EVE_URL=http://127.0.0.1:5000
EVE_BASE = os.getenv("EVE_URL", "http://127.0.0.1:5050")
EVE_LOG_ENDPOINT = f"{EVE_BASE}/log"  # collection name 'log' per assignment
# ---------------------------------------------------
def utc_iso():
    """Return the current UTC timestamp in ISO-8601 format.
    Returns:
        str: UTC timestamp ending with 'Z'.
    """
    return datetime.utcnow().isoformat() + "Z"

def save_json_to_file(obj, path):
    """Write a Python object to a JSON file.
    Parameters:
        obj (dict): JSON-serializable object to save.
        path (str): File path to write to.
    """

    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def post_log(activity, status, details=None):
    """
    Minimal POST to Eve using urllib (no external deps).
    Document schema expected by teammates (simple/common fields).

    Parameters:
        activity (str): Name of the event.
        status (str): "pass" or "fail".
        details (dict, optional): Additional event metadata.

    Returns:
        bool: True if the POST succeeded (HTTP 2xx), otherwise False.
    """
    payload = {
        "activity": activity,             # e.g., "payload_received"
        "status": status,                 # "pass" | "fail"
        "timestamp": utc_iso(),
        "details": details or {}
    }
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(EVE_LOG_ENDPOINT, data=data,
                             headers={"Content-Type": "application/json"})

    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            if 200 <= resp.status < 300:
                return True
    except URLError:
        pass
    return False

def recv_all(conn):
    """Read until peer closes the connection.
    Parameters:
        conn (socket.socket): Connected socket object.

    Returns:
        bytes: Complete byte stream received.
    """
    chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)

def generate_HASHsignature(msg_obj, key):
    """Generate HMAC-SHA256 signature from JSON string of message.
    Parameters:
        msg_obj (dict): JSON object to sign.
        key (str): Shared secret key.

    Returns:
        str or None: Hex-encoded HMAC digest, or None on error.
    """
    try:
        print("\n[HMAC] Generating SHA256 signature...")
        msg_str = json.dumps(msg_obj, sort_keys=True)
        encoded_msg = msg_str.encode("utf-8")
        encoded_key = key.encode("utf-8")

        digester_sha256 = hmac.new(encoded_key, encoded_msg, hashlib.sha256)
        digest_sha256 = digester_sha256.hexdigest()

        print("[HMAC] Signature created successfully.")
        return digest_sha256
    except Exception as e:
        print("[HMAC] Error creating hash:", e)
        return None

def sendUsingSFTPToApp3(jsonPayload, hash_value):
    """Send payload + HMAC to App3 using secure SFTP.
    Parameters:
        jsonPayload (dict): Original JSON payload.
        hash_value (str): HMAC-SHA256 signature.
    """
    try:
        print("\n[SFTP] Preparing to send payload to App3...")

        p = getpass.getpass("Enter SFTP password: ")
        cnopts = pysftp.CnOpts()
        # Host-key verification remains enabled; configure known_hosts.

        # Match App3 expected schema
        payload = {
            "payload": jsonPayload,
            "hmac": hash_value
        }

        # Save to secure_payload.json locally
        with open("secure_payload.json", "w") as f:
            json.dump(payload, f, indent=4)
        print("[SFTP] Local secure_payload.json created.")

        # Connection info (update username for your system)
        cinfo = {
            "cnopts": cnopts,
            "host": os.environ["DIAMOND_SFTP_HOST"],
            "username": "mgj5130",   # replace if needed
            "password": p,
            "port": 1855
        }

        with pysftp.Connection(**cinfo) as sftp:
            print("[SFTP] Connection established with App3.")
            print("[SFTP] Uploading file to App3 receive folder...")

            remote_path = "/home/team2/app3Receive/secure_payload.json"
            sftp.put("secure_payload.json", remote_path)

            print("[SFTP] File uploaded successfully to App3.")
            print("[SFTP] Transmission complete.\n")

    except Exception as e:
        print("[SFTP] Error during SFTP transfer:", e)

def run_server():
    """Run the TLS server that receives payloads from App1, logs events, saves JSON to disk, generates an HMAC, and forwards the data to App3."""

    # TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # plain TCP socket -> wrap after accept
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"App2: listening on {HOST}:{PORT} (TLS). Waiting for App1…")

        while True:
            try:
                client, addr = sock.accept()
                with context.wrap_socket(client, server_side=True) as tls_conn:
                    print(f"App2: TLS version = {tls_conn.version()} from {addr}")
                    post_log("connection_established", "pass",
                             {"peer": f"{addr[0]}:{addr[1]}", "tls": tls_conn.version()})

                    raw = recv_all(tls_conn)
                    print(f"App2: received {len(raw)} bytes")
                    post_log("payload_received", "pass", {"bytes": len(raw)})

                    # decode & parse JSON
                    try:
                        obj = json.loads(raw.decode("utf-8"))
                        save_json_to_file(obj, OUTPUT_FILE)
                        print(f"App2: JSON saved to {OUTPUT_FILE}")
                        post_log("payload_saved", "pass", {"path": OUTPUT_FILE})
                    except json.JSONDecodeError as je:
                        print("App2: ERROR invalid JSON:", je)
                        post_log("json_decode_error", "fail", {"error": str(je)})

                jsonHash = generate_HASHsignature(obj, HASH_KEY)
                sendUsingSFTPToApp3(obj, jsonHash)

            except KeyboardInterrupt:
                print("App2: stopping (Ctrl+C)")
                break
            except Exception as ex:
                print("App2: runtime error:", ex)
                traceback.print_exc()
                post_log("app2_runtime_error", "fail", {"error": str(ex)})

if __name__ == "__main__":
    run_server()
