import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from django.shortcuts import render
from django.http import HttpResponse


# Create your views here.

def index(request):
    return HttpResponse('hi')


def add_server(request):
    if request.method == "GET":
        return render(request, 'kgbapp/index.html')
    elif request.method == "POST":
        sudo_user = request.POST['username']
        server_address = request.POST["address"]
        server_passwd = request.POST["joke"]

        

MASTER_PASSWORD = b"password"

def encrypt_password(server_password):
    server_password = server_password.encode('utf-8')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    enc_passwd = f.encrypt(server_password)
    return (enc_passwd, salt)

def decrypt_password(b_enc_passwd, b_salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b_salt, iterations=10000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_PASSWORD))
    f = Fernet(key)
    s_passwd = f.decrypt(b_enc_passwd)
    return s_passwd.decode('utf-8')