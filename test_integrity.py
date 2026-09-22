"""Offline checks of the actual sender and receiver HMAC functions."""
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class IntegrityTests(unittest.TestCase):
    def test_sign_verify_and_reject_tampering(self):
        # Network adapters are not exercised by this unit test.
        adapters = {"pysftp": types.ModuleType("pysftp"), "Pyro4": types.ModuleType("Pyro4")}
        config = {"DIAMOND_HMAC_KEY": "synthetic-test-key-not-a-credential", "DIAMOND_SFTP_HOST": "localhost"}
        with patch.dict(sys.modules, adapters), patch.dict(os.environ, config):
            sender, receiver = load("App2"), load("App3")
        with patch.object(receiver, "post_log"):
            payload = {"message": "Unicode: café", "value": 7}
            signature = sender.generate_HASHsignature(payload, sender.HASH_KEY)
            self.assertTrue(receiver.verify_hmac({"value": 7, "message": "Unicode: café"}, signature))
            self.assertFalse(receiver.verify_hmac({"value": 8, "message": "Unicode: café"}, signature))

if __name__ == "__main__":
    unittest.main()
