"""
Stub module for six.moves compatibility with python-telegram-bot
"""

class http_client:
    class IncompleteRead(Exception):
        def __init__(self, partial, expected=None):
            self.partial = partial
            self.expected = expected
    
    HTTPException = Exception
    HTTPSConnection = object 