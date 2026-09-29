"""
run.py - App5 Logging Service Entry Point (Project Diamond)

This module starts the App5 logging service using the Eve framework.
App5 receives workflow activity logs from App3 and App4 and stores
them in the MongoDB NoSQL database.

Each log entry includes:
    - activity name
    - pass/fail status
    - timestamp
    - additional details

This service runs as a REST API and listens on port 5050.

To generate HTML doc for this module, run:  pydoc -w run
"""

# Project: Diamond - EVE Server Implementation
# Purpose details: Use CURL to extract a JSON payload from the internet,
                #payload will be saved to a text file,then it will
                #use a network socket programming to send
                #the payload securely using TLS security to the app2.
                #All workflow actions pass or fail will be logged into
                #the activity MongoDB NoSQL database via Eve with a
                #timestamp. Unit tests will confirm all methods are functional
# Course: HCDD 411
# Author: Mark Jachura
# Date Developed: 10/10/2025
# Last Date Changed: N/A
# Rev: 1

from eve import Eve

app = Eve(settings='settings.py')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)
