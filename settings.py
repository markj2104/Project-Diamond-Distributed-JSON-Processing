"""
settings.py - App5 Eve + MongoDB configuration (Project Diamond)

This module defines the Eve configuration settings for App5 logging
service, including the MongoDB connection and the REST resource schema.

Database:
    - Host: localhost
    - Port: 27017
    - Database: Project Diamond

REST Resource:
    - log stores activity logs submitted by Project Diamond apps

The 'log' resource schema includes:
    - activity : string describing the workflow action
    - status: : string allowed value ['pass', 'fail']
    - timestamp : string timestamps for when the action occured
    - details : dict containing additional information

    To generate HTML doc for this module, run:  pydoc -w settings
"""

# Project: Diamond - EVE Server and MongoDB Implementation
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
# Last Date Changed: 10/10/2025
# Rev: 2

MONGO_HOST = 'localhost'
MONGO_PORT = 27017
MONGO_DBNAME = 'project_diamond'

RESOURCE_METHODS = ['GET', 'POST']
ITEM_METHODS = ['GET', 'PATCH', 'DELETE']

DOMAIN = {
    'log': {
        'schema': {
            'activity': {'type': 'string'},
            'status': {'type': 'string', 'allowed': ['pass', 'fail']},
            'timestamp': {'type': 'string'},
            'details': {'type': 'dict'},
        }
    }
}
