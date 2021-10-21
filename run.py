##     Import Libraries & Modules  ##
from flask import Flask, app, abort, redirect, request, session
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
import os
import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask_login import (LoginManager, UserMixin,
                         current_user, login_user, logout_user)
from flask_dance.consumer import oauth_authorized
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.storage.sqla import (OAuthConsumerMixin,
                                               SQLAlchemyStorage)


import requests
from flask_mail import Message, Mail
from flask_share import Share
share = Share()

db = SQLAlchemy()
mail = Mail()

GOOGLE_CLIENT_ID = "280271850627-ndbdmb33ep917kbtm9u9frektj577dh8.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret_280271850627-ndbdmb33ep917kbtm9u9frektj577dh8.apps.googleusercontent.com.json")


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://www.spoonfeedtax.cloud/google/authorized"
)

    
class User(db.Model, UserMixin):
    id = db.Column(db.String(256), primary_key=True)
    email = db.Column(db.String(256), unique=True)
    name = db.Column(db.String(256))

'''
class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship(User)

'''

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'startup@09PM'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mukizbizrmqrsm:b2be1e570f5e7b23e724df2ef4027bc60668b348172091616df3b4b37e742d65@ec2-3-213-146-52.compute-1.amazonaws.com:5432/d3kadk0ovqgq0j'
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 465
    app.config["MAIL_USE_SSL"] = True
    app.config["MAIL_USERNAME"] = 'pavanteja14@gmail.com'
    app.config["MAIL_PASSWORD"] = 'abyqaklzhesxzrmi'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
   # app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=30)


    mail.init_app(app)
    share.init_app(app)

# init SQLAlchemy so we can use it later in our models
    
    db.init_app(app) 
    
    # blueprint for auth routes in our app
    from project.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

     # blueprint for non-auth parts of app
    from project.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    
    
    @login_manager.user_loader
    def load_user(user):
       user = User
       return user

    
    
    return app


    google_blueprint = make_google_blueprint(
        client_id=GOOGLE_CLIENT_ID,
        client_secret=client_secrets_file,
        scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
        offline=False,
        reprompt_consent=True,
        storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
    )

    app.register_blueprint(google_blueprint)
'''
    @oauth_authorized.connect_via(google_blueprint)
    def google_logged_in(blueprint, token):
        resp = blueprint.session.get('/oauth2/v2/userinfo')
        user_info = resp.json()
        user_id = str(user_info['id'])
        oauth = OAuth.query.filter_by(provider=blueprint.name,
                                  provider_user_id=user_id).first()
        if not oauth:
            oauth = OAuth(provider=blueprint.name,
                          provider_user_id=user_id,
                          token=token)
        else:
            oauth.token = token
            db.session.add(oauth)
            db.session.commit()
            login_user(oauth.user)
        if not oauth.user:
            user = User(email=user_info["email"],
                        name=user_info["name"])
            oauth.user = user
            db.session.add_all([user, oauth])
            db.session.commit()
            login_user(user)

        return False

'''

