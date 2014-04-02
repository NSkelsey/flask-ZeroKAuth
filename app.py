import sys
import pprint
import os
from datetime import datetime, timedelta

from flask import Flask, jsonify, session, abort
from flask import request, render_template
from flask_zerokauth import LoginManager, login_required, logout_user

app = Flask(__name__)
app.secret_key = "electric horse battery toothpaste"

login_manager = LoginManager(app)

from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, String, LargeBinary, create_engine
engine = create_engine('sqlite:///test.db',) #echo=True)
Session = sessionmaker(bind=engine)

pp = pprint.PrettyPrinter()

# This is a cheap key value store that would 
# need to replaced by something like redis
SEC_PARAMS = dict()


@app.route('/')
def home():
    return "This is my great webserver!"

@app.route('/register')
def register():
    """Account creation template/view"""
    return render_template('/register.html')

# to serve the static javascript files:
if app.config['DEBUG']:
    from werkzeug import SharedDataMiddleware
    import os
    app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
      '/': os.path.join(os.path.dirname(__file__), 'static')
    })

@app.route('/login')
def login():
    """The view that asks users to log the template should use the login form macro"""
    #TODO insert JS macros into template
    return render_template('/login.html')

@app.route('/admin')
@login_required
def admin():
    return render_template('/admin.html')

@app.route('/logout')
def logout():
    """Deletes session cookie forcing user to reauth"""
    logout_user() 
    return "You are now logged out"

#### FUNCTIONS A LIBRARY-USER MUST DEFINE ####
@login_manager.commit_user
def commit_user_on_create(uname, creds):
    s = Session()
    i_exist = s.query(User).filter_by(name=uname).first()
    if i_exist is not None:
        return False
    new_u = User(uname, 'Cheese', creds) 
    s.add(new_u)
    s.commit()
    s.close()
    return True

@login_manager.get_credentials
def get_user_credentials(uname):
    """Given a user name returns the (s, v) we stored on account creation"""
    s = Session()
    user_obj = s.query(User).filter_by(name=uname).first()
    s.close()
    if user_obj is None:
        return None
    else:
        return user_obj.credentials

@login_manager.get_handshake
def get_user_handshake_state(uname):
    """ returns a dict of the users security params after a valid handshake"""
    return SEC_PARAMS[uname]
    
@login_manager.store_handshake
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
    credentials = Column(String)

    def __init__(self, n, p, creds):
        self.name, self.fav_pizza = n, p
        self.credentials = creds

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'create':
        Base.metadata.create_all(engine)
    else:
        app.run(debug=True)
