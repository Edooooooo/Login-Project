from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
# from phone import Phone

app = Flask(__name__)  # Create Flask Application
bcrypt = Bcrypt(app)  # For hashing passwords
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Connect Database File
app.config['SECRET_KEY'] = 'thisisasecretkey'  # Adding Secret Key to our app, this is used to secure the session cookie
db = SQLAlchemy(app)  # Creating Database

login_manager = LoginManager()  # Provides user session management for Flask
login_manager.init_app(app)  # This allows the LoginManager to work with the Flask application
login_manager.login_view = 'login'  # sets the view function that Flask-Login should redirect to when
# a user tries to access a protected resource without being logged in
choice = []


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def load_user_list():
    return User.query.all()


def search_users_by_name(name):
    return User.query.filter(User.first_name.contains(name))


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    country = db.Column(db.String(50), nullable=False)
    country_code = db.Column(db.Integer, nullable=False)
    region = db.Column(db.String(10), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(100), nullable=False)


class Phone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    phone_code = db.Column(db.String(10), nullable=False)
    number = db.Column(db.String(15), nullable=False)


class Country(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    iso_code = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(150), nullable=False)


class User(db.Model, UserMixin):
    # Table for our Database
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)  # It will be hashed, that's why it has space of 80 chars

    location = db.relationship('Location', backref='user', lazy='joined', cascade="all,delete")
    phones = db.relationship('Phone', backref='user', lazy='joined', cascade="all,delete")


class RegisterForm(FlaskForm):
    username = StringField(
        label="Username",
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"})

    first_name = StringField(
        label="First name",
        validators=[InputRequired(), Length(min=3, max=20)],
        render_kw={"placeholder": "First name"})

    last_name = StringField(
        label="Last name",
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Last name"})

    email = StringField(
        label="Email",
        validators=[InputRequired(), Length(min=4, max=30), Email()],
        render_kw={"placeholder": "Email"})

    phone_code = StringField(
        label="Phone code",
        validators=[InputRequired()],
        render_kw={"placeholder": "Phone Code"})

    phone_number = StringField(
        label="Phone number",
        validators=[InputRequired()],
        render_kw={"placeholder": "Phone Number"})

    country = SelectField(
        label="Country",
        validators=[InputRequired()],
        choices=choice,
        render_kw={"placeholder": "Country"})

    country_code = StringField(
        label="Country Code",
        validators=[InputRequired()],
        render_kw={"placeholder": "Country Code"})

    region = StringField(
        label="Region",
        validators=[InputRequired()],
        render_kw={"placeholder": "Region"})

    city = StringField(
        label="City",
        validators=[InputRequired()],
        render_kw={"placeholder": "City"})

    address = StringField(
        label="Address",
        validators=[InputRequired()],
        render_kw={"placeholder": "Address"})

    password = PasswordField(
        label="Password",
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"})

    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html', title="Authentication System in Flask")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form, title="LogIn")


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = RegisterForm()
    data = current_user
    user_count = User.query.count()
    return render_template('dashboard.html', form=form, obj=data, user_count=user_count)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    new_user = User()

    if form.validate_on_submit() and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        new_user.username = form.username.data
        new_user.first_name = form.first_name.data
        new_user.last_name = form.last_name.data
        new_user.email = form.email.data
        new_user.password = hashed_password

        # Create and add phone information
        new_phone = Phone(
            phone_code=form.phone_code.data,
            number=form.phone_number.data,
            user=new_user
        )
        db.session.add(new_phone)

        # Create and add location information
        new_location = Location(
            country=form.country.data,
            country_code=form.country_code.data,
            region=form.region.data,
            city=form.city.data,
            address=form.address.data,
            user=new_user
        )
        db.session.add(new_location)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    choice.clear()
    for c in Country.query.all():
        choice.append((c.iso_code, c.name))
    # print(choice)

    return render_template('register.html', form=form, obj=new_user, title="Register Page", country_list=choice)


@app.route('/request_user_list', methods=["GET", "POST"])
def request_user_list():
    users = load_user_list()
    return render_template("user_list.html", obj=users, title="Users List")


@app.route('/update/<id>', methods=["GET", "POST"])
def edit_user(id):
    # Get user_id
    user = load_user(id)
    print(user.location[0].country)
    form = RegisterForm()
    return render_template('register.html', obj=user, form=form)


@app.route('/delete/<id>', methods=["GET", "POST"])
@login_required
def delete(id):
    user = load_user(id)
    db.session.delete(user)
    db.session.commit()  # "Write Changes" - in DB

    return redirect(url_for('request_user_list'))


@app.route('/search', methods=["GET", "POST"])
@login_required
def search():
    kw = request.form['searched']
    user_list = search_users_by_name(kw)
    return render_template("user_list.html", obj=user_list)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
