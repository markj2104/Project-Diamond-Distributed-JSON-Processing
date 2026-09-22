"""
Project: Project Diamond - Application 4
Purpose Details:
    App4 receives the Pyro Python object sent from App3 and converts it to JSON.
    All workflow actions pass or fail will be logged into the activity MongoDB
    NoSQL database with a timestamp. Unit tests will confirm all methods are functional.

Course: HCDD 411
Author: Marcos Ruiz
Date Developed: 11/21/2025
Last Date Changed: 11/21/2025
Rev: 1

This module exposes the Reciever class to Pyro so App3 can remotely invoke
methods that accept Python objects and convert them to JSON strings.
"""

import Pyro4
import json


@Pyro4.expose
class Reciever(object):
    """
    Reciever Class
    --------------
    This class receives a Python object from App3 using Pyro4 and converts
    the object into a JSON-formatted string.
    """

    def get_JSON(self, payload):
        """
        Convert an incoming Python object into a JSON string.

        Parameters
        ----------
        payload : object
            The Python object sent from App3. This should contain JSON-serializable data.

        Returns
        -------
        None
        Prints the converted JSON string to the console.
        """

        # payload is already JSON-ready (App3 sends a dict-like object)
        jsonPayload = json.dumps(payload)

        print("Payload received from APP3:", jsonPayload)


# ------------------------- PYRO SERVER -------------------------

if __name__ == "__main__":
    try:
        # Create a Pyro daemon that listens on 0.0.0.0:9090
        daemon = Pyro4.Daemon(host="127.0.0.1", port=9090)
    
        # Register the Reciever object with a name App3 expects
        url = daemon.register(Reciever, objectId="app4.receiver")
    
        print("Ready. Object url =", url)
    
        # Start Pyro4 event loop
        daemon.requestLoop()
    
    except Exception as e:
        print("Error:", e)
