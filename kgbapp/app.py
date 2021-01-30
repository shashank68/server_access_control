import crypt
from shlex import quote
from fabric import Connection, Config

USER = quote("'new3; ls;'")
PASS = quote("123456")


enc_password = quote(crypt.crypt(PASS))
config = Config(overrides={'sudo': {'password': 'shashank123'}})
c = Connection(host='shashank@10.15.17.40', config=config,
               connect_kwargs={'password': 'shashank123'})

res = c.sudo(f'useradd -m -p {enc_password} -s /bin/bash {USER}')
res = c.sudo(f'passwd -e {USER}')


def encrypt_password(server_password):
    import base64
    import os
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend

    server_password = server_password.encode('utf-8')

    MASTER_PASSWORD = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    enc_passwd = f.encrypt(server_password)
    return (enc_passwd, salt)


def decrypt_password(b_enc_passwd, b_salt):
    import base64
    import os
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend

    MASTER_PASSWORD = b"password"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b_salt, iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    s_passwd = f.decrypt(b_enc_passwd)
    return s_passwd.decode('utf-8')
