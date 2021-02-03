# Server Access Control

A django web application that facilitates centralized linux user management through a web interface.

## Features

* Creates a user in a required server. (Automated login)
* Revoke access from a user when needed.
* Generates temporary password during user creation

## Running

```bash
    pip3 install -r requirements.txt
    python3 manage.py makemigrations
    python3 manage.py migrate
    
    python3 manage.py runserver
```

Then add the client servers details from the web interface.