import os
from app import app, db
from models import User
from werkzeug.security import generate_password_hash

# Drop existing database and recreate it
with app.app_context():
    # Drop all tables
    db.drop_all()
    db.create_all()

    # Create default admin user
    admin_user = User(
        username='admin',
        email='admin@school.edu',
        password_hash=generate_password_hash('admin123'),
        is_admin=True,
        full_name='School Administrator',
        bio='System administrator for the school social platform.'
    )

    db.session.add(admin_user)
    db.session.commit()
    print("Database cleared and default admin user created.")