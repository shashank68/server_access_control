from django.db import models

# Create your models here.


class Clientserver(models.Model):
    date_updated = models.DateTimeField('date server was added')
    address = models.CharField(max_length=75)
    sudo_user = models.CharField(max_length=75)
    enc_client_password = models.BinaryField()
    enc_salt = models.BinaryField()

class Userhost(models.Model):
    date_updated = models.DateTimeField('date user-host pair was added')
    server_address = models.CharField(max_length=75)
    user_name = models.CharField(max_length=75)

class User(models.Model):
    date_added = models.DateTimeField('date user was added')
    register_number = models.CharField(max_length=75)
    given_name = models.CharField(max_length=75)
