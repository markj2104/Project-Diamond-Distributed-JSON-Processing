# Project : APP 1 implementation
# Purpose details: Use CURL to extract a JSON payload from the internet,
                #payload will be saved to a text file,then it will
                #use a network socket programming to send
                #the payload securely using TLS security to the app2.
                #All workflow actions pass or fail will be logged into 
                #the activity MongoDB NoSQL database via Eve with a 
                #timestamp. Unit tests will confirm all methods are functional
# Course: IST 411
# Author: Marcos Ruiz 
# Date Developed: 10/8/2025
# Last Date Changed: 10/9/2025
# Rev: 1
import sys, urllib.parse, urllib.request, json, ssl, socket
from datetime import datetime 
"""
Use CURL to extract a JSON payload from the internet,
payload will be saved to a text file,then it will
use a network socket programming to send
the payload securely using TLS security to the app2.
All workflow actions pass or fail will be logged into 
the activity MongoDB NoSQL database via Eve with a 
timestamp. Unit tests will confirm all methods are functional

    Command to generate html doc for this module: pydoc3 -w App1.py
"""
class Payload:
    """
    Payload class encapsulates a payload ID, JSON URL, JSON data, and 
    the time the JSON data was retrieved
    """
    def __init__(self, payloadID, jsonSourceUrl):
        """
        Construct 'Payload' object

        :param payloadID: the payload ID
        :param jsonSourceUrl: The URL location where the JSON was retrieved from
        :return: returns nothing
        """
        self.payloadID = payloadID
        self.jsonData = None
        self.retrievedAt = None
        self.jsonSourceUrl = jsonSourceUrl

    def retrieveJSONPayload(self):
        """
        retrieveJSONPayload gets and assigns jsonData and retrievedAt
        to the payload object

        :return jsonData: Returns the JSON data retrieved using CURL 
        """
        try:
            print("Url: ", self.jsonSourceUrl)
            response = urllib.request.urlopen(self.jsonSourceUrl)
            payload = response.read()
            print("Payload", payload)
        except:
            e = sys.exc_info()[0]
            print("error: %s" %e)
            return None

        self.jsonData = json.loads(payload.decode("utf-8"))
        self.retrievedAt = datetime.now()
        
        print("JSON successfully retrieved!")
        return self.jsonData
# End Payload Class -------------------------------------------------------
# Main class Methods-------------------------------------------------------
def saveJSONtoFile(jsonPayload, filepath):
    """
    Saves the JSON data into a file

    :param jsonPayload: The JSON data
    :param filepath: The file name where the JSON data will be saved
    :return: Returns nothing
    """
    with open(filepath, 'w') as outFile:
            outFile.write(json.dumps(jsonPayload, indent =2))

def sendPayloadToApp2(jsonPayload):
    """
    Sends the JSON payload to APP2 via network sockets

    :param jsonPayload: The JSON data
    :return: Returns nothing
    """
    try:
            print("Client connecting on port 8080 using SSL")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(cafile="server.crt")
            ssl_sock = context.wrap_socket(s, server_hostname="localhost")
            ssl_sock.connect(('localhost', 8080))

            jsonMessage = json.dumps(jsonPayload)
            ssl_sock.sendall(jsonMessage.encode("utf-8"))

            print("JSON message sent: ", jsonMessage)
            print("TLS version: ", ssl_sock.version())
            ssl_sock.close()

    except Exception as e:
        print(e)
        print(ssl_sock.cipher())
        ssl_sock.close

# Main Class --------------------------------------------------------------
if __name__ == "__main__":
    url = "https://jsonplaceholder.typicode.com/posts/1/comments"
    filepath = "jsonDataFile.txt"

    payload = Payload(1, url)
    jsonPayload = payload.retrieveJSONPayload()

    saveJSONtoFile(jsonPayload, filepath)

    sendPayloadToApp2(jsonPayload)
