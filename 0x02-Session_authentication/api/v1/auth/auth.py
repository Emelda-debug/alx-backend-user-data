#!/usr/bin/env python3
"""
class to manage the API authentication.
"""
from flask import request
from typing import List, TypeVar
import fnmatch
import os

class Auth():
    """ Authentication Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ method to check if auth is required"""
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True
    

    def authorization_header(self, request=None) -> str:
        """ method to get authorization header"""
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header
    
    def current_user(self, request=None) -> TypeVar('User'):
        """Method to get user from request"""
        return None
    
    def session_cookie(self, request=None):
        """value of _my_session_id cookie from request object"""
        if request is None:
            return None
        session_name = os.getenv('SESSION_NAME')
        return request.cookies.get(session_name)
