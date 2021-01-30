from django.db import models

# Create your models here.


class Clientserver(models.Model):
    date_updated = models.DateTimeField('date server was added')
    name = models.CharField(max_length=75)
    address = models.CharField(max_length=75, primary_key=True)
    sudo_user = models.CharField(max_length=75)
    enc_client_password = models.BinaryField()
    enc_salt = models.BinaryField()

    def __str__(self):
        return self.address


class Userhost(models.Model):
    date_updated = models.DateTimeField('date user-host pair was added')
    server_address = models.CharField(max_length=75)
    user_name = models.CharField(max_length=75)

    def __str__(self):
        return self.user_name


class User(models.Model):
    date_added = models.DateTimeField('date user was added')
    register_number = models.CharField(max_length=75)
    given_name = models.CharField(max_length=75)

    def __str__(self):
        return self.given_name
