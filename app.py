from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp, DataRequired
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    tel = db.Column(db.String(14), nullable=False, unique=True)
    password = db.Column(db.String(30), nullable=False)

class RegisterForm(FlaskForm):
    name = StringField(validators = [InputRequired(), Length
    (min=8, max=20)], render_kw={"placeholder": "John Doe"})

    email = EmailField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "Johndoe@yahoo.co"})

    tel = StringField(validators = [InputRequired(), DataRequired(), Regexp(r'^\+234?\d{9,15}$', message="Enter a valid number."), Length
    (min=13, max=14)], render_kw={"placeholder": "234 must be incuded"})
    
    password = PasswordField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "password"})

    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = EmailField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "Johndoe@yahoo.co"})

    password = PasswordField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "password"})

    submit =SubmitField("Login")
    

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, password = form.password.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            try:
                return redirect (url_for('dashboard'))
            except:
                flash("Error signing user in")
                return redirect(url_for('login'))
        else:
            flash("Invalid Credentials")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.email == form.email.data) |
            (User.tel == form.tel.data)
            ).first()

        if existing_user:
            flash("Phone Number or Email Taken")
            return redirect(url_for('register'))
        else:
            new_user = User(name=form.name.data,  email=form.email.data, tel=form.tel.data, password=form.password.data)
            try:
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))
            except:
                flash("There was an issue creating your account")
                return redirect(url_for('register'))

    return render_template("register.html", form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():

    db.session.commit()
    return render_template('verify_otp.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.name)

@app.route('/setting')
@login_required
def setting():
    return render_template("setting.html", name=current_user.name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out")
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
