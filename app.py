# pip install flask flask-login Flask-Security-Too flask-sqlalchemy email-validator flask-bcrypt
from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user
from flask_security import Security, SQLAlchemySessionUserDatastore, UserMixin, RoleMixin
from flask_bcrypt import Bcrypt 

app = Flask(__name__, template_folder='Templates')

 
bcrypt = Bcrypt(app) 

# path to sqlite database
# this will create the db file in instance
# if database not present already
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pvb.sqlite3"
# needed for session cookies
app.config["SECRET_KEY"] = "boeloeboeloe"
# hashes the password and then stores in the database
app.config['SECURITY_PASSWORD_SALT'] = "MY_SECRET"
# allows new registrations to application
app.config['SECURITY_REGISTERABLE'] = True
# to send automatic registration email to user
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False


db = SQLAlchemy()
db.init_app(app)
# # # runs the app instance
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)

# create table in database for assigning roles
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))   

class Users(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String(250),nullable=False, server_default='')
    active = db.Column(db.Boolean())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=True)
    # confirmed_at = db.Column(db.DateTime())
    # current_login_at = db.Column(db.DateTime())
    # last_login_at = db.Column(db.DateTime())
    # current_login_ip = db.Column(db.String(255)) 
    # last_login_ip = db.Column(db.String(255)) 
    # login_count = db.Column(db.Integer()) 
        # backreferences the user_id from roles_users table
    roles = db.relationship('Role', secondary=roles_users, backref='roled')

# create table in database for storing roles
class Role(RoleMixin, db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)



# load users, roles for a session
user_datastore = SQLAlchemySessionUserDatastore(db.session, Users, Role)
security = Security(app, user_datastore)
# UserDatastore.set_uniquifier()

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)


# creates all database tables
# push context manually to app
with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/signin", methods=["GET","POST"])
def signin():
    msg=''
    if request.method == 'POST':
        user = Users.query.filter_by(
            username=request.form.get("email")).first()
        
        # if user exist
        if user:
            password=request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') 
            if user.password == hashed_password:
                login_user(user)
                return redirect(url_for("home"))
            else:
                msg="wrong password"
                return render_template("signin.html", msg=msg)
        
        # if user does not exist
        else:
            msg="User doesn't exist"
            return render_template("signin.html", msg=msg)
         
    else:
        return render_template("signin.html", msg=msg)
    


@app.route("/signup", methods=["GET","POST"])
def signup(): #signup():
    msg=""
    # if the form is submitted
    if request.method == 'POST':
    # check if user already exists
        user = Users.query.filter_by(email=request.form['email']).first()
        msg=""
        # if user already exists render the msg
        if user:
            msg="User already exist"
            # render signup.html if user exists
            return redirect("signup.html", msg=msg) 
         
        # if user doesn't exist
        else: 
            # store the user to database
            password=request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') 
            user = Users(email=request.form['email'], active=1, password=hashed_password)
            # store the role
            role = Role.query.filter_by(id=request.form['options']).first()
            user.roles.append(role)
            
            # commit the changes to database
            db.session.add(user)
            db.session.commit()
            
            # login the user to the app
            # this user is current user
            login_user(user)
            # redirect to index page
            return redirect(url_for('home'))
         
    # case other than submitting form, like loading the page itself
    else:
        return render_template("signup.html", msg=msg)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__': 
    app.run(debug=True) 






