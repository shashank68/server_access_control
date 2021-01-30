import uuid
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import *
from django.utils import timezone

import crypt
from shlex import quote
from fabric import Connection, Config
# Create your views here.


def index(request):
    return HttpResponse('hi')


def add_server(request):
    if request.method == "GET":
        return render(request, 'addserver.html')
    elif request.method == "POST":
        # todo purify these values
        print(request.POST)
        sudo_user = request.POST["username"]
        server_address = request.POST["address"]
        server_passwd = request.POST["password"]
        (b_enc_pass, b_salt) = encrypt_password(server_passwd)

        if len(Clientserver().filter(server_address=server_address)) != 0:
            # server address exists redirect to edit section
            pass
        else:
            srv = Clientserver(date_updated=timezone.now(), address=server_address,
                               sudo_user=sudo_user, enc_client_password=b_enc_pass, enc_salt=b_salt)
            srv.save()
    return redirect('/addserver')

def create_user(request):
    if request.method == "GET":
        return render(request, 'createserver.html')
    elif request.method == "POST":
        # todo purify values
        username = request.POST["username"]
        server_address = request.POST["server_address"]

        if len(Clientserver().filter(server_address=server_address)) == 0:
            # A server with this this address is not registered. Sending to addserver page
            return redirect('/addserver')
        else:
            s_user_passwd = str(uuid.uuid4())[0:10]
            enc_user_passwd = quote(crypt.crypt(s_user_passwd))
            adduser(server_address, quote(username), enc_user_passwd)

        
def adduser(server_address, username,enc_user_passwd):
    server = Clientserver().filter(server_address=server_address)

    sudo_username = server.sudo_user
    b_enc_sudo_passwd = server.enc_client_password
    b_salt = server.enc_salt
    sudo_passwd = decrypt_password(b_enc_sudo_passwd, b_salt)
  
    config = Config(overrides={'sudo': {'password': sudo_passwd}})
    connect_kwargs = {'password': sudo_passwd}
    host_addr = sudo_username + "@" + server_address
    with Connection(host=host_addr, config=config, connect_kwargs=connect_kwargs) as conn:
        conn.sudo(f'useradd -m -p {enc_user_passwd} -s /bin/bash {username}')

MASTER_PASSWORD = b"password"


def encrypt_password(server_password):
    server_password = server_password.encode('utf-8')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    enc_passwd = f.encrypt(server_password)
    return (enc_passwd, salt)


def decrypt_password(b_enc_passwd, b_salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b_salt,
                     iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    s_passwd = f.decrypt(b_enc_passwd)
    return s_passwd.decode('utf-8')
