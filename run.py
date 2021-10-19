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

import requests
from flask_mail import Message, Mail
from flask_share import Share
share = Share()

db = SQLAlchemy()
mail = Mail()

from flask_login import LoginManager

GOOGLE_CLIENT_ID = "280271850627-sd8php857k66pvd224643lk56ksu67kc.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret_280271850627-sd8php857k66pvd224643lk56ksu67kc.apps.googleusercontent.com.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://developmentspoonfeed.herokuapp.com/callback"
)


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'startup@09PM'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mukizbizrmqrsm:b2be1e570f5e7b23e724df2ef4027bc60668b348172091616df3b4b37e742d65@ec2-3-213-146-52.compute-1.amazonaws.com:5432/d3kadk0ovqgq0j'
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 465
    app.config["MAIL_USE_SSL"] = True
    app.config["MAIL_USERNAME"] = 'pavanteja14@gmail.com'
    app.config["MAIL_PASSWORD"] = 'abyqaklzhesxzrmi'

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
    login_manager.login_view = 'google.login'
    login_manager.init_app(app)
    
    
    

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        
        user_id = session["google_id"]
        return user_id


    return app
