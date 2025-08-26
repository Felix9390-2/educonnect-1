import os
import logging
from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP for development
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.strip():
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///school_social.db"
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# File upload configuration
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')

# Initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Import models to ensure tables are created
    import models
    db.create_all()
    
    # Create default admin user if it doesn't exist
    from models import User
    from werkzeug.security import generate_password_hash
    
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
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
            logging.info("Created default admin user (username: admin, password: admin123)")
        
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        # If there's a schema mismatch, recreate the database
        db.drop_all()
        db.create_all()
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
        logging.info("Database recreated and default admin user created (username: admin, password: admin123)")

# Import routes after app initialization
from routes import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
