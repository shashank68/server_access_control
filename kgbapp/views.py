import uuid
import crypt

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Clientserver, Userhost
from django.utils import timezone

from shlex import quote
from json import dumps

from utils import *


def index(request):
    authenticated = True
    if authenticated:
        servers = Clientserver.objects.all()
        server_list = []
        for server in servers:
            server_list.append([server.address, server.sudo_user])
        noservers = True if len(server_list) == 0 else False
        context = {"servers": server_list, "noservers": noservers}
        return render(request, 'index.html', context)


def add_server(request):
    if request.method == "GET":
        return render(request, 'addserver.html')
    elif request.method == "POST":
        # todo purify these values
        sudo_user = request.POST["username"]
        server_address = request.POST["address"]
        server_passwd = request.POST["password"]
        (b_enc_pass, b_salt) = encrypt_password(server_passwd)

        if is_address_invalid(server_address):
            # the address is neither a valid hostname nor a valid ip address
            pass
        elif is_username_invalid(sudo_user):
            # invalid username
            pass
        elif len(Clientserver.objects.filter(address=server_address)) != 0:
            # server address exists redirect to edit section
            pass
        else:
            srv = Clientserver(date_updated=timezone.now(), address=server_address,
                               sudo_user=sudo_user, enc_client_password=b_enc_pass, enc_salt=b_salt)
            srv.save()
    return redirect('/addserver')


def manage_server(request):
    if request.method == "GET":
        return redirect('/')
    elif request.method == "POST":
        server_address = request.POST["address"]
        action = request.POST["actiontype"]
        if is_address_invalid(server_address):
            pass
        else:
            server = Clientserver.objects.filter(address=server_address)[0]
            if action == "view":
                context = {
                    'address': server_address,
                    'sudo_user': server.sudo_user,
                }
                return render(request, 'manageserver.html', context)
            elif action == "update":
                if "changeusername" in request.POST:
                    username = request.POST["username"]
                    if is_username_invalid(username):
                        pass
                    else:
                        server.sudo_user = username
                        server.save()
                if "changepassword" in request.POST:
                    passwd = request.POST["password"]
                    (b_enc_pass, b_salt) = encrypt_password(passwd)
                    server.enc_client_password = b_enc_pass
                    server.enc_salt = b_salt
                    server.save()
                return redirect('/')
        return HttpResponse("ERROR modifying")


def delete_server(request):
    if request.method == "GET":
        return render(request, 'index.html')
    else:
        server_address = request.POST["address"]
        if is_address_invalid(server_address):
            pass
        elif len(Clientserver.objects.filter(address=server_address)) == 0:  # no such server
            pass
        else:
            users = Userhost.objects.filter(server_address=server_address)
            if "remove_users" in request.POST:
                # delete the users from the server if selected
                conn = make_connection(server_address)
                for usr in users:
                    res = conn.sudo(
                        f'deluser --remove-home {quote(usr.user_name)}')
                conn.close()

            for usr in users:  # remove users frm database
                usr.delete()
            server = Clientserver.objects.get(address=server_address)
            server.delete()
            return redirect('/')
        return HttpResponse("ERROR :/")


def create_user(request):
    if request.method == "GET":
        servers = Clientserver.objects.all()
        server_list = []
        for server in servers:
            server_list.append(server.address)
        noservers = True if len(server_list) == 0 else False
        context = {"servers": server_list, "noservers": noservers}
        return render(request, 'createuser.html', context)
    elif request.method == "POST":
        username = request.POST["username"]
        server_address = request.POST["server_address"]

        is_sudo = True if "sudopriv" in request.POST else False
        if is_address_invalid(server_address):  # not a valid host or ip
            pass
        elif is_username_invalid(username):  # not a valid username
            pass
        elif len(Clientserver.objects.filter(address=server_address)) == 0:
            # A server with this this address is not registered. Sending to addserver page
            return redirect('/addserver')
        elif len(Userhost.objects.filter(server_address=server_address).filter(user_name=username)) != 0:
            # This user is already recorded in database
            pass
        else:
            s_user_passwd = str(uuid.uuid4())[0:10]
            enc_user_passwd = quote(crypt.crypt(s_user_passwd))

            conn = make_connection(server_address)
            res1 = conn.sudo(
                f'useradd -m -p {enc_user_passwd} -s /bin/bash {quote(username)}')
            exit_code = res1.exited
            if exit_code == 1:  # some error. Maybe due to lack of permission
                pass
            elif exit_code == 9:  # username already exits
                pass
            elif exit_code == 0:
                if is_sudo:
                    conn.sudo(f'usermod -aG sudo {quote(username)}')
                # expire the password. user has to change on next login
                res2 = conn.sudo(f'passwd -e {quote(username)}')
                conn.close()
                if res2.exited != 0:  # some error. Should refer passwd man page
                    pass
                else:  # hopefully user is created. Add him to database
                    userhost = Userhost(date_updated=timezone.now(),
                                        server_address=server_address, user_name=username)
                    userhost.save()
                    context = {'created_user_password': s_user_passwd,
                               "username": username, "server_addr": server_address}
                    return render(request, 'createuser.html', context)
                    return HttpResponse(s_user_passwd)
            conn.close()
        return HttpResponse("ERROR: Couldnt add user")


def delete_user(request):
    if request.method == "GET":
        servers = Clientserver.objects.all()
        serv_dict = {}
        for server in servers:
            userhosts = Userhost.objects.filter(server_address=server.address)
            if len(userhosts) != 0:
                serv_dict[server.address] = [usr.user_name for usr in userhosts]
        nousers = True if len(serv_dict) == 0 else False
        serv_dict = dumps(serv_dict)
        context = {'serv_dict': serv_dict, 'nousers': nousers}
        return render(request, 'deleteuser.html', context)
    else:
        username = request.POST["username"]
        server_address = request.POST["server_address"]

        if is_username_invalid(username) or is_address_invalid(server_address):
            # invalid inputs
            pass
        elif len(Userhost.objects.filter(server_address=server_address).filter(user_name=username)) == 0:
            # this user-host doesn't exist in database;
            pass
        elif len(Clientserver.objects.filter(address=server_address)) == 0:
            # this server isn't in database
            pass
        else:
            conn = make_connection(server_address)
            res = conn.sudo(f'deluser --remove-home {quote(username)}')
            conn.close()
            exit_code = res.exited
            if exit_code != 0:  # error. Needs to be handled manually by logging into server
                pass
            else:
                try:
                    userhost = Userhost.objects.get(
                        user_name=username, server_address=server_address)
                    userhost.delete()
                    return HttpResponse("User deleted succesfully")
                except:
                    print("Multiple objects!!")
                    pass
        return HttpResponse("Error: Couldn't succesfully delete user")
