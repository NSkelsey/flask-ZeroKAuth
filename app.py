import sys
import pprint

from flask import Flask, jsonify
from flask import request, render_template

app = Flask(__name__)

from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, LargeBinary, create_engine
engine = create_engine('sqlite:///test.db', echo=True)
Session = sessionmaker(bind=engine)


# zkauth imports
from srp_server import Verifier
from binascii import hexlify, a2b_hex
import struct

pp = pprint.PrettyPrinter()

#TODO delete me
SEC_PARAMS = dict()

@app.route('/')
def home():
    return "This is my great webserver!"


# ESTABLISHMENT; here we receive s,v from the client and store it
@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        data = request.get_json()
        uname = data['username']
        creds = data['credentials']
        new_u = User(uname, 'Cheese', creds) 
        s = Session()
        s.add(new_u)
        s.commit()

        return "User created: " + uname
    else:
        return render_template('/create.html')


# AUTHENTICATION; here we validate an existing user
@app.route('/login')
def login():
    return render_template('/login.html')

# client posts I, A, server responds with s, B
@app.route('/handshake', methods=['POST'])
def handshake():
    data = request.get_json()
    uname = str(data['username'])
    A = data['A']
    creds = get_user_credentials(uname)
    if creds is None:
        raise ValueError("bad credentials")
    s, v = unpack(creds)
    veri = Verifier(s=s, v=v, I=uname)
    (s, B) = veri.compute_B(A)

    store_user_handshake_state(uname, veri.params())

    return jsonify({'s':s, 'B':B})


# client posts M1, server responds with M2
@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    uname = str(data['username'])
    state = get_user_handshake_state(uname)
    veri = Verifier(**state)
    M1 = data['M1']
    try:
        veri.verify_M1(M1)
    except AssertionError:
       # print "M1's do not match"
       # print 'GEND M1 ', veri.M1
       # print 'RECD M1 ', M1
       # print 'SERV SECRET: ', veri.S
        print "="*50
        pp.pprint(veri.__dict__)
        print "="*50
        return "M1's do not match bailing"
    
    M2 = veri.compute_M2()

    return jsonify({'M2': M2})
    

# There is a subtle bug in here, some S's are not getting through....
# packs s, v for blob storage
def pack(creds):
    s, v = creds['s'], creds['v']
    # 64 bit salt
    b_s = struct.pack('>Q', s)
    # 128 bit v binary repr
    b_v = a2b_hex(hex(v)[2:-1]) 
    #assert len(b_s) == 8
    #assert len(b_v) >= 16
    return b_s + b_v
    

# unpacks s, v from blob storage
def unpack(creds):
    b_s = creds[:8]
    # struck.unpack wants to return a tuple
    s = struct.unpack('>Q', b_s)[0]
    b_v = creds[8:]
    v = long(hexlify(b_v), 16)
    print "LENGTHS"
    print "s %d, v %d" % (len(hex(s)), len(hex(v)))
    #assert len(b_s) == 8
    #assert len(b_v) >= 16
    return (s, v)


#### FUNCTIONS A LIBRARY-USER MUST DEFINE ####

def get_user_credentials(uname):
    """Given a user name return the (s, v) we stored on account creation"""
    s = Session()
    user_obj = s.query(User).filter_by(name=uname).first()
    return user_obj.credentials

def get_user_handshake_state(uname):
    """ returns a dict of the users security params after a valid handshake"""
    return SEC_PARAMS[uname]
    
def store_user_handshake_state(uname, params):
    """Stores the handshake parameters in some cache layer so we can rebuild the verifier object"""
    SEC_PARAMS[uname] = params
    return True


from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    """
    programmer defined class, all they should need to store is (s, v)
    """
    __tablename__ = "users"

    name = Column(String, primary_key=True)
    fav_pizza = Column(String)
    credentials = Column(LargeBinary)

    def __init__(self, n, p, creds):
        self.name, self.fav_pizza = n, p
        self.credentials = pack(creds)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'create':
        Base.metadata.create_all(engine)
    else:
        app.run(debug=True)
