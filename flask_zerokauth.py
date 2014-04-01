__version__ = '0.0.1'
__author__ = 'Nick Skelsey'

import struct
from binascii import hexlify, a2b_hex
from functools import wraps

from flask import current_app, session, abort, request, jsonify
from flask import _app_ctx_stack 

# local imports
from srp_server import Verifier


# CONFIGS
import pprint

pp = pprint.PrettyPrinter()

class LoginManager(object):

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

        #TODO document each one of these functions
        self.commit_user_callback = None
        self.get_credentials_callback = None
        self.get_handshake_callback = None
        self.store_handshake_callback = None

    def init_app(self, app):
        app.login_manager = self
        # route registration
        app.add_url_rule('/create', 'create', create, methods=['GET', 'POST'])
        app.add_url_rule('/handshake', 'handshake', handshake, methods=['POST'])
        app.add_url_rule('/verify', 'verify', verify, methods=['POST'])

    def commit_user(self, callback):
        self.commit_user_callback = callback
        return callback

    def get_credentials(self, callback):
        self.get_credentials_callback = callback
        return callback

    def get_handshake(self, callback):
        self.get_handshake_callback = callback
        return callback

    def store_handshake(self, callback):
        self.store_handshake_callback = callback
        return callback


def process_inc(raw_dict):
    """This function processes incoming json and converts all hex strings in the provided dict into longs and ints and returns a new dict with those values properly formatted"""
    clean_dict = {}
    for k, v in raw_dict.iteritems():
        assert type(v) == unicode
        clean_dict[k] = long(v, 16)
    return clean_dict


# CUSTOM ROUTING FUNCTIONS -- THIS IS THE SRP PROTOCOL

# ESTABLISHMENT; here we receive s,v from the client and store it
def create():
    if request.method == 'POST':
        # TODO check for bad data
        data = request.get_json()
        uname = data['username']
        _dict = process_inc(data['credentials'])
        print _dict
        creds = pack(_dict)
        worked = current_app.login_manager.commit_user_callback(uname, creds)
        # TODO add more checks here
        if worked:
            return "User created: " + uname
        else:
            print "User creation failed hard"
            abort(400)
    else:
        return render_template('/create.html')


# AUTHENTICATION; here we validate an existing user
# client posts I, A, server responds with s, B
def handshake():
    data = request.get_json()
    uname = str(data['username'])
    A = data['A']
    _raw = current_app.login_manager.get_credentials_callback(uname) 
    s, v = unpack(_raw)
    veri = Verifier(s=long(s), v=v, I=uname)
    (s, B) = veri.compute_B(A)

    current_app.login_manager.store_handshake_callback(uname, veri.params())

    return jsonify({'s':s, 'B':B})


# client posts M1, server responds with M2
def verify():
    data = request.get_json()
    uname = str(data['username'])
    state = current_app.login_manager.get_handshake_callback(uname)
    veri = Verifier(**state)
    veri.compute_secret()
    M1 = data['M1']
    try:
        veri.verify_M1(M1)
    except AssertionError:
        print "M1's do not match or M1 is not of type long"
        pp.pprint(veri.__dict__)
        return "Bailing out of interaction"
    
    M2 = veri.compute_M2()

    _set_user_session(uname)

    return jsonify({'M2': M2})
    

# packs s, v for blob storage
def pack(creds):
    s, v = long(creds['s']), creds['v']
    assert type(s) == long and type(v) == long
    # Strips longs of trailing L
    b_s = struct.pack('>Q', s)
    b_v = a2b_hex(hex(v)[2:-1])
    assert len(b_s) == 8
    assert len(b_v) >= 16
    return b_s + b_v
    
# unpacks s, v from blob storage
def unpack(raw):
    b_s = raw[:8]
    s = long(struct.unpack('>Q', b_s)[0])
    b_v = raw[8:]
    v = long(hexlify(b_v), 16)
    return (s, v)

def _set_user_session(user_id):
    """Setups a users session cookies for future access"""
    session['user_id'] = user_id

def _remove_user_session():
    return session.pop('user_id', None) is not None

def logout_user():
    _remove_user_session()

def login_required(func):
    """A login forcing decorator"""
    @wraps(func)
    def decorator(*args, **kwargs):
        u_id = session.get('user_id')
        if u_id is not None: 
            print "logged in!"
            return func(*args, **kwargs)
        else:
            out = func(*args, **kwargs)
            print "login was no good"
            return abort(403)
    return decorator


