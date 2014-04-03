__version__ = '0.0.1'
__author__ = 'Nick Skelsey'

import struct
from functools import wraps

from flask import current_app, session, abort, request, jsonify
from flask import _app_ctx_stack 

# local imports
from .srp_server import Verifier
from .utils import _hex


# CONFIGS

# DEBUG
import pprint
pp = pprint.PrettyPrinter()

class LoginManager(object):

    def __init__(self, app=None, api_path=""):
        """
        Initializes a LoginManager with an optional app object. 
        :param app: The optional :class: `flask.Flask` object to configure
        :type app: :class: `flask.Flask`
        :param api_path: The url path that the zka views live under, an 
        example would be api_path="/srp_proto".
        :type api_path: str
        """
        self.base_api_path = api_path

        if app is not None:
            self.init_app(app)

        #TODO document each one of these functions
        self.commit_user_callback = None
        self.get_credentials_callback = None
        self.get_handshake_callback = None
        self.store_handshake_callback = None

    def init_app(self, app):
        """
        Configures an app with all the needed routes for the srp protocol 
        to function correctly. Note there are several callbacks that need 
        to be defined as well for the plugin to work correctly
        :param app: The optional :class: `flask.Flask` object to configure
        :type app: :class: `flask.Flask`
        :param api_path: The url path that the zka views live under
        :type api_path: str
        """
        app.login_manager = self
        base_p = self.base_api_path
        # route registration
        app.add_url_rule(base_p + '/create', 'create', create, methods=['GET', 'POST'])
        app.add_url_rule(base_p + '/handshake', 'handshake', handshake, methods=['POST'])
        app.add_url_rule(base_p + '/verify', 'verify', verify, methods=['POST'])

        # TODO better static import strategy
        from werkzeug import SharedDataMiddleware
        import os
        app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
          '/': os.path.join(os.path.dirname(__file__), 'static')
        })


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


def process_inc(raw_dict, num_elems):
    """This function processes incoming json and converts all hex strings 
    in the provided dict into longs and returns a new dict with those values 
    properly formatted. It also coerces the username field into a string
    """
    clean_dict = {}
    assert len(raw_dict) == num_elems, "%s has wrong num of elements" % str(raw_dict)
    for k, v in raw_dict.iteritems():
        assert type(v) == unicode, "%s's value has wrong type." % k
        if k == u'username':
            clean_dict[k] = str(v)
        else:
            try:
                clean_dict[k] = long(v, 16)
            except ValueError:
                raise AssertionError("Value: %s should be a hex str" % v)
    return clean_dict


# CUSTOM ROUTING FUNCTIONS -- THIS IS THE SRP PROTOCOL
# ESTABLISHMENT; here we receive s,v from the client and store it
def create():
    c_dict = request.get_json()
    try:
        c_dict = process_inc(c_dict, 3)
    except AssertionError as e:
        print e
        abort(400)
    uname = c_dict['username']
    # pass pack a dict of s, v
    creds = pack(c_dict)
    worked = current_app.login_manager.commit_user_callback(uname, creds)
    # TODO add more checks here
    if worked:
        return "User created: " + uname
    else:
        print "User creation failed hard"
        abort(400)


# AUTHENTICATION; here we validate an existing user
# client posts I, A, server responds with s, B
def handshake():
    c_dict = request.get_json()
    try:
        c_dict = process_inc(c_dict, 2)
    except AssertionError:
        abort(400)
    uname = c_dict['username']
    A = c_dict['A']
    _raw = current_app.login_manager.get_credentials_callback(uname) 
    s, v = unpack(_raw)
    veri = Verifier(s=s, v=v, I=uname)
    (s, B) = veri.compute_B(A)

    current_app.login_manager.store_handshake_callback(uname, veri.params())

    # for testing XMLRequest timeout---------#
    # import time                              #
    # time.sleep(1)                            #
    # ---------------------------------------#

    return jsonify({'s': _hex(s), 'B': _hex(B)})


# client posts M1, server responds with M2
def verify():
    c_dict = request.get_json()
    try:
        c_dict = process_inc(c_dict, 2)
    except AssertionError:
        abort(400)
    uname = c_dict['username']
    state = current_app.login_manager.get_handshake_callback(uname)
    veri = Verifier(**state)
    veri.compute_secret()
    M1 = c_dict['M1']
    try:
        veri.verify_M1(M1)
    except AssertionError:
        print "M1's do not match or M1 is not of type long"
        pp.pprint(veri.__dict__)
        abort(403)
    
    M2 = veri.compute_M2()
    _set_user_session(uname)

    return jsonify({'M2': _hex(M2)})
    

# packs s, v for hex string storage
def pack(creds):
    """
    Packs a dict of credentials for storage as a hex string
    :param creds: A dict object containing s and v as keys to hex strs
    :type creds: :class: dict
    """
    s, v = creds['s'], creds['v']
    assert type(s) == long and type(v) == long
    # Strips longs of trailing L
    b_s = _hex(s)
    b_v = _hex(v)
    return b_s + '|' + b_v
    
# unpacks s, v from hex str storage
def unpack(raw):
    b_s, b_v = raw.split('|')
    s = long(b_s, 16)
    v = long(b_v, 16)
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


