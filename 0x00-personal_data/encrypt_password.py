#!/usr/bin/env python3
"""
This module provides functions for hashing and validating passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.
    """

    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.
    """

    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
