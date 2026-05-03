"""SSH connection helpers using credentials from environment.

Supports both the Ubuntu server (target) and Kali attacker via separate
context managers, both reading from .env.
"""
import os
import paramiko
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()


def _connect(host_var: str, user_var: str, pwd_var: str,
             port_var: str = None) -> paramiko.SSHClient:
    """Generic SSH connect that reads env vars by name."""
    host = os.getenv(host_var)
    user = os.getenv(user_var)
    pwd  = os.getenv(pwd_var)
    port = int(os.getenv(port_var, "22")) if port_var else 22

    if not all([host, user, pwd]):
        raise RuntimeError(
            f"Missing SSH credentials. Check .env has {host_var}, {user_var}, {pwd_var}."
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=pwd, port=port)
    return client


@contextmanager
def ssh_connection():
    """Connect to the Ubuntu server (the target/sensor)."""
    client = _connect("SERVER_HOST", "SERVER_USER", "SERVER_PASSWORD", "SERVER_PORT")
    try:
        yield client
    finally:
        client.close()


@contextmanager
def kali_connection():
    """Connect to the Kali attacker box."""
    client = _connect("KALI_HOST", "KALI_USER", "KALI_PASSWORD")
    try:
        yield client
    finally:
        client.close()