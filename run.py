##     Import Libraries & Modules  ##
from flask import Flask, app
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from flask_login import LoginManager


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'startup@09PM'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://mukizbizrmqrsm:b2be1e570f5e7b23e724df2ef4027bc60668b348172091616df3b4b37e742d65@ec2-3-213-146-52.compute-1.amazonaws.com:5432/d3kadk0ovqgq0j'

# init SQLAlchemy so we can use it later in our models
    
    db.init_app(app)
from models import User

    db.create_all()
    users= User.query.all()
    
    # blueprint for auth routes in our app
    from project.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

     # blueprint for non-auth parts of app
    from project.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from project.models import User
    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))


    return app
