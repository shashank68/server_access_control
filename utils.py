from os import urandom
from re import compile
from base64 import urlsafe_b64encode, urlsafe_b64decode
from fabric import Connection, Config

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from kgbapp.models import Clientserver

LINUX_USERNAME_REGEX = '^[a-z][-a-z0-9]*$'
IP_ADDRESS_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
HOSTNAME_REGEX = "^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"

username_regex = compile(LINUX_USERNAME_REGEX)
ip_regex = compile(IP_ADDRESS_REGEX)
hostname_regex = compile(HOSTNAME_REGEX)


MASTER_PASSWORD = b"password"


def make_connection(server_address):
    server = Clientserver.objects.filter(address=server_address)[0]
    sudo_passwd = decrypt_password(server.enc_client_password, server.enc_salt)
    config = Config(overrides={'sudo': {'password': sudo_passwd}, 'connect_kwargs': {
                    'password': sudo_passwd}, 'user': server.sudo_user})
    conn = Connection(host=server_address, config=config)
    return conn


def encrypt_password(server_password):
    server_password = server_password.encode('utf-8')
    salt = urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=10000, backend=default_backend())
    key = urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    enc_passwd = f.encrypt(server_password)
    return (enc_passwd, salt)


def decrypt_password(b_enc_passwd, b_salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b_salt,
                     iterations=10000, backend=default_backend())
    key = urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    s_passwd = f.decrypt(b_enc_passwd)
    return s_passwd.decode('utf-8')


def is_address_invalid(server_address):
    return ip_regex.fullmatch(server_address) is None and hostname_regex.fullmatch(server_address) is None

def is_username_invalid(username):
    return username_regex.fullmatch(username) is None