# OrderGambia

A simple food ordering app built with Flask, Flask-SQLAlchemy, and Flask-WTF. Users can register, login, and order from restaurants. Restaurants can manage menus and orders.

## Features
- User registration and login
- Restaurant registration and login
- Menu management for restaurants
- Order placement and status management
- SQLite database

## Setup
1. Clone the repo: `git clone https://github.com/ordergambia/OrderGambia.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Run the app: `python app.py`
4. Access at `http://127.0.0.1:5000/`

## Usage
- Register as a user or restaurant.
- Users: Place orders from dashboards.
- Restaurants: Add menu items and update order statuses.

## Development
- Use GitHub Codespaces for online editing.
- Test changes and commit regularly.

Note: This is for development. For production, use a secure secret key, a production database (e.g., PostgreSQL), and a WSGI server like Gunicorn.
