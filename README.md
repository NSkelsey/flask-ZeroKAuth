Flask-ZeroKAuth
====

An alternative "securer" login library for flask.
----

This library implements a zero knowledge login protocol know as the Secure Remote Password protocol (SRP6a, to be exact). The interesting thing about this protocol is that instead of storing a hash of your password and a salt, flask-ZeroKAuth will only store enough information for a user to be able prove that they know their password. Nothing more. This means if your database gets hacked, your user's passwords will not be comprimised!

### How is that possible?!
Its actually quite simple to understand, read [this](http://en.wikipedia.org/wiki/Zero-knowledge_proof#Abstract_example)! Seriously though, if this is all new to you just use Flask-Login. This is expiremental software.

### References Used
To build this extension we based our implemenation off of three things:

* [Wikipedia](http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
* [RFC 5054](http://tools.ietf.org/html/rfc5054)
* This [PDF]() (which we created ourselves)

### Installation
You can install the package from pip using this command:

```
pip install flask-zerokauth
```

### Usage
This application mimics the functionality and api of Flask-Login. Therefore we use the following conventions


```
"""This example assumes db is your hook into persistent data storage"""
from flask_zerokauth import LoginManager, login_required, logout_user, login_route
from flask import Flask, render_template


app = Flask()

login_manager = LoginManager(app)

@app.route('/admin')
@login_required
def admin():
    return "Only a logged in user can visit this url"

@app.route('/login')
@login_route
def login():
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return "This clears a logged in users session"

@login_manager.get_credentials
def get_creds(username):
    return db.get(username).creds

@login_manager.commit_user
def add_creds(username, credentials):
    user = db.get(username)
    user.creds = credentials
    db.commit()

@login_manger.get_handshake
def get_handshake(username):
    return db.get(username).hs_params

@login_manager.store_handshake
def store_users_handshake(username, params):
    user = db.get(username)
    user.hs_params = params
    db.commit()

```

### LICENSE

BSD
