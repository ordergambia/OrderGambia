
# app.py

from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secure random key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ordfrom flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure key later
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ordergambia.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    menu_items = db.relationship('MenuItem', backref='restaurant', lazy=True)
    orders = db.relationship('Order', backref='restaurant', lazy=True)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(20), nullable=False, default='Pending')

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register Restaurant')

class OrderForm(FlaskForm):
    restaurant = SelectField('Restaurant', coerce=int, validators=[DataRequired()])
    menu_item = SelectField('Menu Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Place Order')

class MenuForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=1, max=50)])
    price = FloatField('Price', validators=[DataRequired()])
    submit = SubmitField('Add Menu Item')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html', form=form)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form, title='User Login')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', orders=orders, user=user)

@app.route('/register_restaurant', methods=['GET', 'POST'])
def register_restaurant():
    if 'restaurant_id' in session:
        return redirect(url_for('restaurant_dashboard'))
    form = RestaurantForm()
    if form.validate_on_submit():
        if Restaurant.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('register_restaurant.html', form=form)
        hashed_password = generate_password_hash(form.password.data)
        restaurant = Restaurant(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(restaurant)
        db.session.commit()
        flash('Restaurant registered! You can now log in.', 'success')
        return redirect(url_for('restaurant_login'))
    return render_template('register_restaurant.html', form=form)

@app.route('/restaurant_login', methods=['GET', 'POST'])
def restaurant_login():
    if 'restaurant_id' in session:
        return redirect(url_for('restaurant_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        restaurant = Restaurant.query.filter_by(email=form.email.data).first()
        if restaurant and check_password_hash(restaurant.password, form.password.data):
            session['restaurant_id'] = restaurant.id
            flash('Restaurant logged in!', 'success')
            return redirect(url_for('restaurant_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form, title='Restaurant Login')

@app.route('/restaurant_dashboard')
def restaurant_dashboard():
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    restaurant = Restaurant.query.get(session['restaurant_id'])
    orders = Order.query.filter_by(restaurant_id=restaurant.id).all()
    menu_items = MenuItem.query.filter_by(restaurant_id=restaurant.id).all()
    return render_template('restaurant_dashboard.html', orders=orders, menu_items=menu_items, restaurant=restaurant)

@app.route('/add_menu', methods=['GET', 'POST'])
def add_menu():
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    form = MenuForm()
    if form.validate_on_submit():
        menu_item = MenuItem(name=form.name.data, price=form.price.data, restaurant_id=session['restaurant_id'])
        db.session.add(menu_item)
        db.session.commit()
        flash('Menu item added successfully!', 'success')
        return redirect(url_for('restaurant_dashboard'))
    return render_template('add_menu.html', form=form)

@app.route('/update_order_status/<int:order_id>/<string:new_status>')
def update_order_status(order_id, new_status):
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    order = Order.query.get_or_404(order_id)
    if order.restaurant_id != session['restaurant_id']:
        flash('You are not authorized to update this order.', 'danger')
        return redirect(url_for('restaurant_dashboard'))
    if new_status not in ['Pending', 'Accepted', 'Completed', 'Cancelled']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('restaurant_dashboard'))
    order.status = new_status
    db.session.commit()
    flash('Order status updated!', 'success')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/order', methods=['GET', 'POST'])
def place_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = OrderForm()
    form.restaurant.choices = [(r.id, r.name) for r in Restaurant.query.order_by('name').all()]
    if request.method == 'POST':
        selected_restaurant = form.restaurant.data
        form.menu_item.choices = [(m.id, f"{m.name} (${m.price})") for m in MenuItem.query.filter_by(restaurant_id=selected_restaurant).order_by('name').all()]
    else:
        form.menu_item.choices = []
    if form.validate_on_submit():
        order = Order(
            user_id=session['user_id'],
            restaurant_id=form.restaurant.data,
            menu_item_id=form.menu_item.data,
            quantity=form.quantity.data
        )
        db.session.add(order)
        db.session.commit()
        flash('Your order has been placed!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('order.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)ergambia.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    orders = db.relationship('Order', backref='user', lazy=True)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    menu_items = db.relationship('MenuItem', backref='restaurant', lazy=True)
    orders = db.relationship('Order', backref='restaurant', lazy=True)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(20), nullable=False, default='Pending')

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RestaurantForm(FlaskForm):
    name = StringField('Restaurant Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register Restaurant')

class OrderForm(FlaskForm):
    restaurant = SelectField('Restaurant', coerce=int, validators=[DataRequired()])
    menu_item = SelectField('Menu Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Place Order')

class MenuForm(FlaskForm):
    name = StringField('Item Name', validators=[DataRequired(), Length(min=1, max=50)])
    price = FloatField('Price', validators=[DataRequired()])
    submit = SubmitField('Add Menu Item')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html', form=form)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form, title='User Login')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', orders=orders, user=user)

@app.route('/register_restaurant', methods=['GET', 'POST'])
def register_restaurant():
    if 'restaurant_id' in session:
        return redirect(url_for('restaurant_dashboard'))
    form = RestaurantForm()
    if form.validate_on_submit():
        if Restaurant.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('register_restaurant.html', form=form)
        hashed_password = generate_password_hash(form.password.data)
        restaurant = Restaurant(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(restaurant)
        db.session.commit()
        flash('Restaurant registered! You can now log in.', 'success')
        return redirect(url_for('restaurant_login'))
    return render_template('register_restaurant.html', form=form)

@app.route('/restaurant_login', methods=['GET', 'POST'])
def restaurant_login():
    if 'restaurant_id' in session:
        return redirect(url_for('restaurant_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        restaurant = Restaurant.query.filter_by(email=form.email.data).first()
        if restaurant and check_password_hash(restaurant.password, form.password.data):
            session['restaurant_id'] = restaurant.id
            flash('Restaurant logged in!', 'success')
            return redirect(url_for('restaurant_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form, title='Restaurant Login')

@app.route('/restaurant_dashboard')
def restaurant_dashboard():
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    restaurant = Restaurant.query.get(session['restaurant_id'])
    orders = Order.query.filter_by(restaurant_id=restaurant.id).all()
    menu_items = MenuItem.query.filter_by(restaurant_id=restaurant.id).all()
    return render_template('restaurant_dashboard.html', orders=orders, menu_items=menu_items, restaurant=restaurant)

@app.route('/add_menu', methods=['GET', 'POST'])
def add_menu():
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    form = MenuForm()
    if form.validate_on_submit():
        menu_item = MenuItem(name=form.name.data, price=form.price.data, restaurant_id=session['restaurant_id'])
        db.session.add(menu_item)
        db.session.commit()
        flash('Menu item added successfully!', 'success')
        return redirect(url_for('restaurant_dashboard'))
    return render_template('add_menu.html', form=form)

@app.route('/update_order_status/<int:order_id>/<string:new_status>')
def update_order_status(order_id, new_status):
    if 'restaurant_id' not in session:
        return redirect(url_for('restaurant_login'))
    order = Order.query.get_or_404(order_id)
    if order.restaurant_id != session['restaurant_id']:
        flash('You are not authorized to update this order.', 'danger')
        return redirect(url_for('restaurant_dashboard'))
    if new_status not in ['Pending', 'Accepted', 'Completed', 'Cancelled']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('restaurant_dashboard'))
    order.status = new_status
    db.session.commit()
    flash('Order status updated!', 'success')
    return redirect(url_for('restaurant_dashboard'))

@app.route('/order', methods=['GET', 'POST'])
def place_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = OrderForm()
    form.restaurant.choices = [(r.id, r.name) for r in Restaurant.query.order_by('name').all()]
    if request.method == 'POST':
        selected_restaurant = form.restaurant.data
        form.menu_item.choices = [(m.id, f"{m.name} (${m.price})") for m in MenuItem.query.filter_by(restaurant_id=selected_restaurant).order_by('name').all()]
    else:
        form.menu_item.choices = []
    if form.validate_on_submit():
        order = Order(
            user_id=session['user_id'],
            restaurant_id=form.restaurant.data,
            menu_item_id=form.menu_item.data,
            quantity=form.quantity.data
        )
        db.session.add(order)
        db.session.commit()
        flash('Your order has been placed!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('order.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
