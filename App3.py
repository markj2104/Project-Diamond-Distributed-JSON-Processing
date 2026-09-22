# Project: Project Diamond – App 3
# Purpose Details: Receive secure SFTP payload from App2, verify HMAC-SHA256, and email verified payload to team
# Course: HCDD 411
# Author: Mark Jachura & Kelly Indigo Rawlings
# Date Developed: 10/27/2025
# Last Date Changed: 10/30/2025
# Revision: 4

"""
App3 — Project Diamond
----------------------
This module receives a secure JSON payload from App2 over SFTP, verifies its
integrity using HMAC-SHA256, compresses the verified payload using gzip, sends
the payload to App4 using the Pyro ORB interface, and distributes email 
notifications to all team members. All workflow events—including SFTP download,
HMAC verification, Pyro transmission, compression actions, and email delivery—
are logged to the Eve/MongoDB REST API.

Workflow Steps:
1. Download secure_payload.json from App2 via SFTP.
2. Validate the received payload’s HMAC signature using a shared secret key.
3. If valid:
       • Compress the payload using gzip.
       • Send the payload object to App4 via Pyro4.
       • Email the verified payload to all team members using threaded delivery.
4. Record detailed pass/fail logs for each workflow step.

This module can be documented with:
    pydoc3 -w App3.py
"""

import pysftp
import smtplib
import json
import hmac
import hashlib
import threading
from email.mime.text import MIMEText
import getpass
import os
import sys
from urllib import request as urlrequest
from urllib.error import URLError
from datetime import datetime, timezone
import gzip
import Pyro4

# CONFIGURATION
HOST = os.environ["DIAMOND_SFTP_HOST"]
PORT = 1855

# These paths now match what App2 uploads
REMOTE_PATH = "/home/team2/app3Receive/secure_payload.json"
LOCAL_PATH = "secure_payload_copy.json"

SMTP_SERVER = os.getenv("DIAMOND_SMTP_HOST", "localhost")
SMTP_PORT = 465
FROM_ADDR = os.getenv("DIAMOND_FROM_ADDR", "")
TEAM_EMAILS = []  # Add only explicitly authorized recipients.

# Pyro ORB config to send payload to App4
PYRO_APP4_URI = os.getenv("APP4_URI", "PYRO:app4.receiver@localhost:9090")

# Where to store compressed payload
COMPRESSED_PATH = "secure_payload_payload.gz"

# Shared secret key used by App2 and App3 for HMAC verification
HMAC_KEY = os.environ["DIAMOND_HMAC_KEY"].encode("utf-8")

# Eve REST endpoint for activity logs (your teammates run Eve on 5000)
# override with ENV if needed, e.g., EVE_URL=http://127.0.0.1:5000
EVE_BASE = os.getenv("EVE_URL", "http://127.0.0.1:5050")
EVE_LOG_ENDPOINT = f"{EVE_BASE}/log"  # collection name 'log' per assignment

# --------------------------------------------------------------------- #
def utc_iso():
    return datetime.utcnow().isoformat() + "Z"

def post_log(activity, status, details=None):
    payload = {
        "activity": activity,
        "status": status,
        "timestamp": utc_iso(),
        "details": details or {}
    }
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        EVE_LOG_ENDPOINT,
        data=data,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            if 200 <= resp.status < 300:
                return True
    except URLError as e:
        print(f"[LOG] Eve logging failed (offline?): {e}")
    except Exception as e:
        print(f"[LOG] Unexpected error posting to Eve: {e}")
    return False


def download_payload(username, password):
    """Connect to SFTP, download JSON payload from App2"""
    try:
        print("\n[SFTP] Connecting to server...")
        post_log("sftp_connect", "pass", {"host": HOST, "port": PORT})
        cnopts = pysftp.CnOpts()
        # Host-key verification remains enabled; configure known_hosts.

        cinfo = {
            "cnopts": cnopts,
            "host": HOST,
            "username": username,
            "password": password,
            "port": PORT
        }

        with pysftp.Connection(**cinfo) as sftp:
            print("[SFTP] Connection established.")
            print(f"[SFTP] Downloading {REMOTE_PATH} ...")
            sftp.get(REMOTE_PATH, LOCAL_PATH)
            print("[SFTP] File downloaded successfully.")
            post_log("payload_downloaded", "pass", {"path": LOCAL_PATH})

    except Exception as e:
        print(f"[SFTP] Error occurred: {e}")
        post_log("payload_downloaded", "fail", {"error": str(e)})
        sys.exit(1)



def verify_hmac(payload_data, expected_hmac):
    """Verify that HMAC-SHA256 matches the received message"""
    try:
        print("\n[HMAC] Verifying message integrity...")
        encoded_msg = json.dumps(payload_data, sort_keys=True).encode("utf-8")
        digester = hmac.new(HMAC_KEY, encoded_msg, hashlib.sha256)
        computed_hmac = digester.hexdigest()

        if hmac.compare_digest(computed_hmac, expected_hmac):
            print("[HMAC] Verification Successful! Data integrity confirmed.")
            post_log("hmac_verified", "pass")
            return True
        else:
            print("[HMAC] Verification Failed! Data may have been modified.")
            post_log("hmac_verified", "fail")
            return False
    except Exception as e:
        print(f"[HMAC] Error verifying signature: {e}")
        post_log("hmac_verified", "fail", {"error": str(e)})
        return False


def send_email(to_address, subject, message_body):
    """Send email message to a single address"""
    try:
        msg = MIMEText(message_body)
        msg["Subject"] = subject
        msg["From"] = FROM_ADDR
        msg["To"] = to_address

        print(f"[EMAIL] Connecting to {SMTP_SERVER} for {to_address} ...")
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
            s.sendmail(FROM_ADDR, [to_address], msg.as_string())
            print(f"[EMAIL] Message sent successfully to {to_address}.")
            post_log("email_sent", "pass", {"recipient": to_address})

    except Exception as e:
        print(f"[EMAIL] Error sending email to {to_address}: {e}")
        post_log("email_sent", "fail", {"recipient": to_address, "error": str(e)})


def send_emails_threaded(subject, body):
    """Send emails to all team members using threading"""
    print("\n[THREADING] Sending emails to team...")
    threads = []

    for addr in TEAM_EMAILS:
        t = threading.Thread(target=send_email, args=(addr, subject, body))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("[THREADING] All email threads completed.")
    post_log("email_threading", "pass")

def compress_payload(payload, out_path=COMPRESSED_PATH):
    """Compress the JSON payload using gzip."""
    try:
        print("\n[GZIP] Compressing payload...")
        json_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        with gzip.open(out_path, "wb") as gz:
            gz.write(json_bytes)

        print(f"[GZIP] Payload compressed to {out_path}")
        post_log("gzip_compress", "pass", {"path": out_path})
        return out_path
    except Exception as e:
        print(f"[GZIP] Error compressing payload: {e}")
        post_log("gzip_compress", "fail", {"error": str(e)})
        return None

def send_to_app4_via_pyro(payload):
    """
    Use Pyro ORB (Pyro4) to send the Python object (payload) to App4.
    Assumes App4 exposes get_JSON(payload) on the Reciever class.
    """
    try:
        print("\n[PYRO] Connecting to App4 ORB...")
        post_log("pyro_connect", "pass", {"uri": PYRO_APP4_URI})

        with Pyro4.Proxy(PYRO_APP4_URI) as proxy:
            proxy.get_JSON(payload)

        print("[PYRO] Payload successfully sent to App4.")
        post_log("pyro_send", "pass")
        return True
    except Exception as e:
        print(f"[PYRO] Error sending payload to App4 via Pyro: {e}")
        post_log("pyro_send", "fail", {"error": str(e)})
        return False

def main():
    try:
        print("--------------------------------------------------")
        print("   Project Diamond - App 3 (HMAC + Email)   ")
        print("--------------------------------------------------")

        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")

        # Step 1: Download JSON payload from App2
        download_payload(username, password)

        # Step 2: Read payload and verify HMAC
        print(f"\n[FILE] Reading downloaded JSON from {LOCAL_PATH}")
        with open(LOCAL_PATH, "r") as f:
            data = json.load(f)
        post_log("json_read", "pass", {"path": LOCAL_PATH})

        if "payload" not in data or "hmac" not in data:
            print("[ERROR] JSON missing 'payload' or 'hmac' fields.")
            post_log("json_read", "fail")
            sys.exit(1)

        payload = data["payload"]
        hmac_received = data["hmac"]

        verified = verify_hmac(payload, hmac_received)

        # Step 3: If verified, compress, send via Pyro, then email
        if verified:
            subject = "Project Diamond - Verified Payload from App3"
            body = json.dumps(payload, indent=4)

            # 3a: Compress the JSON payload
            compressed_path = compress_payload(payload)

            # 3b: Send Python object to App4 using Pyro
            pyro_ok = send_to_app4_via_pyro(payload)

            # 3c: Send emails (threaded)
            send_emails_threaded(subject, body)

            # 3d: Overall App3 workflow log
            overall_status = "pass" if (compressed_path and pyro_ok) else "fail"
            post_log("app3_process", overall_status, {
                "compressed_path": compressed_path,
                "pyro_ok": pyro_ok
            })
        else:
            print("[APP3] File integrity failed. No emails sent.")
            post_log("app3_process", "fail", {"reason": "HMAC verification failed"})

    except Exception as e:
        print(f"[APP3] Unexpected error: {e}")
        post_log("app3_runtime_error", "fail", {"error": str(e)})


    finally:
        print("\n[APP3] Process complete. Exiting.")
        post_log("app3_exit", "pass")

if __name__ == "__main__":
    main()
