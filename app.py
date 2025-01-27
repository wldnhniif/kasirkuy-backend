from flask import Flask, request, jsonify, send_file, send_from_directory, after_this_request, make_response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
from functools import wraps
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
import uuid
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import re
from flask_talisman import Talisman
import time
import sys
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from contextlib import contextmanager
from werkzeug.datastructures import FileStorage

# Load environment variables
load_dotenv()

# Validate required environment variables
required_env_vars = [
    'JWT_SECRET_KEY',
    'FRONTEND_URL'
]

missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
    sys.exit(1)

# Initialize Flask app
app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

# Get frontend URLs
FRONTEND_URL = os.getenv('FRONTEND_URL')
ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5000'
]

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:3000",
            "https://kasirkuy-one.vercel.app"
        ],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Configure Content Security Policy
content_security_policy = {
    'default-src': ["'self'", "http://localhost:3000", "https://kasirkuy-one.vercel.app"],
    'img-src': ["'self'", "data:", "blob:", "http://localhost:3000", "https://kasirkuy-one.vercel.app", "*"],
    'script-src': ["'self'", "'unsafe-inline'", "http://localhost:3000", "https://kasirkuy-one.vercel.app"],
    'style-src': ["'self'", "'unsafe-inline'", "http://localhost:3000", "https://kasirkuy-one.vercel.app"],
    'connect-src': ["'self'", "http://localhost:3000", "https://kasirkuy-one.vercel.app"],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"]
}

# Add CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin, X-Requested-With'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Range, X-Content-Range'
        
        # Handle OPTIONS request
        if request.method == 'OPTIONS':
            response.headers['Access-Control-Max-Age'] = '3600'
            response.status_code = 204
            return response
            
    # Print debug info for all API requests
    if request.path.startswith('/api/'):
        print(f"Request: {request.method} {request.path}")
        print(f"Headers: {dict(request.headers)}")
        print(f"Response Status: {response.status_code}")
            
    return response

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print("Error: DATABASE_URL environment variable is not set")
    sys.exit(1)

# Create SQLAlchemy engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    products = relationship("Product", back_populates="user")

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    image_url = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="products")

# Database context manager
@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)

# Initialize database
init_db()

# Enable security headers with Talisman
talisman = Talisman(
    app,
    force_https=False,
    session_cookie_secure=False,
    session_cookie_http_only=True,
    strict_transport_security=False,
    content_security_policy=content_security_policy,
    content_security_policy_nonce_in=['script-src'],
    force_file_save=False,
    content_security_policy_report_only=False,
    content_security_policy_report_uri=None
)

# Security Constants
FAILED_LOGIN_ATTEMPTS = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = 15 * 60  # 15 minutes in seconds
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour default
PASSWORD_HASH_METHOD = 'pbkdf2:sha256:600000'  # Strong password hashing
AUTH_COOKIE_NAME = 'kasirkuy_auth_token'  # Specific cookie name for our application

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    print(f"Created upload folder: {UPLOAD_FOLDER}")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configure allowed file extensions
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    print(f"Created upload folder at: {UPLOAD_FOLDER}")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
print(f"Upload folder configured at: {UPLOAD_FOLDER}")

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # Change in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)  # Increase token expiry to 7 days
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']  # Allow both headers and cookies
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF protection for development
app.config['JWT_COOKIE_SECURE'] = False  # Allow non-HTTPS cookies in development
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_ACCESS_COOKIE_NAME'] = AUTH_COOKIE_NAME
app.config['JWT_REFRESH_COOKIE_NAME'] = f"{AUTH_COOKIE_NAME}_refresh"
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

# Initialize JWT
jwt = JWTManager(app)

@jwt.unauthorized_loader
def unauthorized_response(callback):
    print("JWT unauthorized: Missing token")  # Debug log
    print("Cookies:", request.cookies)  # Debug log
    print("Headers:", dict(request.headers))  # Debug log
    return jsonify({
        'message': 'Missing Authorization Header'
    }), 401

@jwt.invalid_token_loader
def invalid_token_response(error_string):
    print(f"JWT invalid token: {error_string}")  # Debug log
    print("Cookies:", request.cookies)  # Debug log
    print("Headers:", dict(request.headers))  # Debug log
    return jsonify({
        'message': 'Invalid token'
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("JWT expired token")  # Debug log
    print("Token payload:", jwt_payload)  # Debug log
    return jsonify({
        'message': 'Token has expired'
    }), 401

@jwt.user_lookup_error_loader
def user_lookup_error(jwt_header, jwt_payload):
    print(f"JWT user lookup error: {jwt_payload}")  # Debug log
    return jsonify({
        'message': 'User not found'
    }), 401

# Helper functions for database operations
def create_user(username, password, is_admin=False):
    with get_db() as db:
        try:
            hashed_password = generate_password_hash(password, method=PASSWORD_HASH_METHOD)
            db_user = User(
                username=username,
                password=hashed_password,
                is_admin=is_admin
            )
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            return db_user
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            db.rollback()
            return None

def get_user_by_username(username):
    with get_db() as db:
        try:
            user = db.query(User).filter(User.username == username).first()
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'password': user.password,
                    'is_admin': user.is_admin,
                    'created_at': user.created_at.isoformat() if user.created_at else None
                }
            return None
        except Exception as e:
            print(f"Error getting user: {str(e)}")
            return None

def get_user_by_id(user_id):
    with get_db() as db:
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'password': user.password,
                    'is_admin': user.is_admin,
                    'created_at': user.created_at.isoformat() if user.created_at else None
                }
            return None
        except Exception as e:
            print(f"Error getting user by ID: {str(e)}")
            return None

def create_product(name, price, image_url, user_id):
    with get_db() as db:
        db_product = Product(
            name=name,
            price=price,
            image_url=image_url,
            user_id=user_id
        )
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        return db_product.id

def get_products_by_user(user_id):
    with get_db() as db:
        try:
            products = db.query(Product).filter(Product.user_id == user_id).all()
            return [
                {
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'image_url': product.image_url,
                    'user_id': product.user_id,
                    'created_at': product.created_at.isoformat() if product.created_at else None
                }
                for product in products
            ]
        except Exception as e:
            print(f"Error getting products: {str(e)}")
            return []

def update_product(product_id, data):
    with get_db() as db:
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return False
        
        for key, value in data.items():
            if hasattr(product, key):
                setattr(product, key, value)
        
        db.commit()
        return True

def delete_product(product_id):
    with get_db() as db:
        product = db.query(Product).filter(Product.id == product_id).first()
        if not product:
            return False
        db.delete(product)
        db.commit()
        return True

def update_user(user_id, data):
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        
        for key, value in data.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        db.commit()
        return True

def delete_user(user_id):
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        db.delete(user)
        db.commit()
        return True

# Add decorator for strict rate limiting on auth endpoints
def strict_rate_limit():
    return limiter.limit(
        "3 per minute, 10 per hour, 20 per day",
        error_message="Too many attempts. Please try again later."
    )

# Add decorator for moderate rate limiting on protected endpoints
def moderate_rate_limit():
    return limiter.limit(
        "30 per minute, 300 per hour",
        error_message="Request limit exceeded. Please try again later."
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Admin middleware
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            response = get_user_by_id(user_id)
            user = response if response else None
            if not user or not user['is_admin']:
                return jsonify({"error": "Admin access required"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def get_device_fingerprint():
    """Generate a device fingerprint based on headers and IP"""
    user_agent = request.headers.get('User-Agent', '')
    ip_address = request.remote_addr
    # Combine user agent and IP to create a unique device ID
    device_id = f"{ip_address}_{user_agent}"
    return device_id, ip_address

# Password validation function
def is_password_valid(password):
    """
    Password must:
    - Be at least 8 characters long
    - Contain at least one uppercase letter
    - Contain at least one lowercase letter
    - Contain at least one number
    - Contain at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

# Routes
@app.route('/api/register', methods=['POST'])
@strict_rate_limit()
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        print(f"Register attempt for username: {username}")  # Debug log
        
        # Validate input
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
            
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return jsonify({'message': 'Username must be 3-20 characters long and contain only letters, numbers, and underscores'}), 400
            
        # Validate password strength
        is_valid, message = is_password_valid(password)
        if not is_valid:
            return jsonify({'message': message}), 400
            
        # Check if username already exists
        existing_user = get_user_by_username(username)
        if existing_user:
            return jsonify({'message': 'Username already exists'}), 409
            
        # Create user
        user = create_user(username, password)
        if not user:
            return jsonify({'message': 'Failed to create user'}), 500
            
        print(f"User created successfully: {user.username}")  # Debug log
        return jsonify({'message': 'User registered successfully'}), 201
            
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'message': 'An error occurred during registration', 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
@strict_rate_limit()
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        username = data.get('username')
        password = data.get('password')
        
        print(f"Login attempt for username: {username}")  # Debug log
        
        # Validate input
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Get device info for security tracking
        device_id, ip_address = get_device_fingerprint()
        
        # Check for too many failed attempts
        if ip_address in FAILED_LOGIN_ATTEMPTS:
            attempts, last_attempt_time = FAILED_LOGIN_ATTEMPTS[ip_address]
            if attempts >= MAX_FAILED_ATTEMPTS:
                time_passed = time.time() - last_attempt_time
                if time_passed < LOCKOUT_TIME:
                    return jsonify({
                        'message': f'Too many failed attempts. Please try again in {int((LOCKOUT_TIME - time_passed) / 60)} minutes'
                    }), 429

        # Get user from database
        user = get_user_by_username(username)
        if not user:
            record_failed_login(ip_address)
            return jsonify({'message': 'Invalid username or password'}), 401

        # Verify password
        if not check_password_hash(user['password'], password):
            record_failed_login(ip_address)
            return jsonify({'message': 'Invalid username or password'}), 401

        # Clear failed login attempts on successful login
        if ip_address in FAILED_LOGIN_ATTEMPTS:
            del FAILED_LOGIN_ATTEMPTS[ip_address]

        # Create access token
        token = create_access_token(
            identity=str(user['id']),  # Convert user ID to string
            additional_claims={
                'username': user['username'],
                'is_admin': user['is_admin'],
                'device_id': device_id
            }
        )

        # Create response
        response = jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'is_admin': user['is_admin']
            }
        })

        # Set cookie
        response.set_cookie(
            AUTH_COOKIE_NAME,
            token,
            max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds(),
            httponly=True,
            secure=app.config['JWT_COOKIE_SECURE'],
            samesite=app.config['JWT_COOKIE_SAMESITE'],
            path=app.config['JWT_ACCESS_COOKIE_PATH']
        )

        print(f"Login successful for user: {username}")  # Debug log
        print(f"Token generated: {token}")  # Debug log
        print(f"Response cookies: {response.headers.get('Set-Cookie')}")  # Debug log

        return response

    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug log
        return jsonify({'message': 'An error occurred during login'}), 500

def verify_password(password, stored_password_hash):
    """Verify a password against a stored hash"""
    try:
        # Check if the stored password is already hashed
        if stored_password_hash.startswith('pbkdf2:'):
            return check_password_hash(stored_password_hash, password)
        else:
            # If not hashed (like the default admin password), compare directly
            return stored_password_hash == password
    except Exception as e:
        print(f"Password verification error: {str(e)}")
        return False

def record_failed_login(ip_address):
    """Record failed login attempt and update lockout status"""
    current_time = time.time()
    if ip_address in FAILED_LOGIN_ATTEMPTS:
        attempts, _ = FAILED_LOGIN_ATTEMPTS[ip_address]
        FAILED_LOGIN_ATTEMPTS[ip_address] = (attempts + 1, current_time)
    else:
        FAILED_LOGIN_ATTEMPTS[ip_address] = (1, current_time)

@app.route('/api/products', methods=['GET'])
@jwt_required()
@moderate_rate_limit()
def get_products():
    try:
        # Get user ID from JWT token
        user_id = get_jwt_identity()
        print(f"Fetching products for user_id: {user_id}")  # Debug log
        
        if user_id is None:
            print("No user ID in token")  # Debug log
            return jsonify({"error": "User not authenticated"}), 401
        
        # Verify user exists
        user = get_user_by_id(user_id)
        if not user:
            print(f"User {user_id} not found")  # Debug log
            return jsonify({"error": "User not found"}), 404
        
        # Get products
        products = get_products_by_user(user_id)
        print(f"Found {len(products)} products")  # Debug log
        
        # Add user info to each product
        for product in products:
            product['user_name'] = user['username']
        
        return jsonify({"products": products}), 200
        
    except Exception as e:
        print(f"Error getting products: {str(e)}")  # Debug log
        return jsonify({"error": str(e)}), 500

@app.route('/api/products', methods=['POST'])
@jwt_required()
@moderate_rate_limit()
def add_product():
    try:
        print("Creating product...")
        print("Files:", request.files)
        print("Form:", request.form)
        
        name = request.form.get('name')
        price = request.form.get('price')
        
        if not name or not price:
            return jsonify({'message': 'Name and price are required'}), 400
        
        # Handle image upload
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Check file type
                allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
                file_ext = os.path.splitext(file.filename)[1].lower()
                
                if file_ext not in allowed_extensions:
                    return jsonify({'message': 'Invalid file type. Allowed types: jpg, jpeg, png, gif, webp'}), 400
                
                image_url = save_file(file)
                if not image_url:
                    return jsonify({'message': 'Failed to save image'}), 500
                print(f"Image saved with URL: {image_url}")
        
        with get_db() as db:
            product = Product(
                name=name,
                price=float(price),
                image_url=image_url,
                user_id=get_jwt_identity()
            )
            db.add(product)
            db.commit()
            db.refresh(product)
            
            return jsonify({
                'message': 'Product created successfully',
                'product': {
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'image_url': product.image_url
                }
            }), 201
            
    except Exception as e:
        print(f"Error creating product: {str(e)}")
        return jsonify({'message': 'Failed to create product'}), 500

@app.route('/api/products/<int:product_id>', methods=['PATCH'])
@jwt_required()
@moderate_rate_limit()
def update_product(product_id):
    try:
        print(f"Updating product {product_id}...")
        print("Files:", request.files)
        print("Form:", request.form)
        
        with get_db() as db:
            # Get product and verify ownership
            product = db.query(Product).filter(
                Product.id == product_id,
                Product.user_id == get_jwt_identity()
            ).first()
            
            if not product:
                return jsonify({'message': 'Product not found or unauthorized'}), 404
            
            # Update basic info
            if 'name' in request.form:
                product.name = request.form['name']
            if 'price' in request.form:
                product.price = float(request.form['price'])
            
            # Handle image update
            if 'image' in request.files:
                file = request.files['image']
                if file.filename:
                    # Delete old image if exists
                    if product.image_url:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_url)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                            print(f"Deleted old image: {old_image_path}")
                    
                    # Save new image
                    image_url = save_file(file)
                    if image_url:
                        product.image_url = image_url
                        print(f"New image saved with URL: {image_url}")
            
            db.commit()
            db.refresh(product)
            
            return jsonify({
                'message': 'Product updated successfully',
                'product': {
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'image_url': product.image_url
                }
            })
            
    except Exception as e:
        print(f"Error updating product: {str(e)}")
        return jsonify({'message': 'Failed to update product'}), 500

@app.route('/api/products/<string:product_id>', methods=['DELETE'])
@jwt_required()
@moderate_rate_limit()
def delete_user_product(product_id):
    try:
        print(f"Delete request for product ID: {product_id}")
        user_id = get_jwt_identity()
        print(f"User ID: {user_id}")
        
        # Check if product exists and belongs to user
        product_response = get_products_by_user(user_id)
        print(f"Product check response: {product_response}")
        
        if not product_response:
            return jsonify({"error": "Product not found or unauthorized"}), 404
        
        # Delete product and handle image cleanup
        response = delete_product(product_id)
        print(f"Delete response: {response}")
        
        if not response:
            return jsonify({"error": "Failed to delete product"}), 500
        
        # Run general cleanup
        cleanup_old_images()
        
        return jsonify({"message": "Product deleted successfully"}), 200
        
    except Exception as e:
        print(f"Error deleting product: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/uploads/<path:filename>')
def serve_file(filename):
    """Serve uploaded files with proper headers and error handling"""
    try:
        # Log request details
        print(f"Serving file request for: {filename}")
        
        # Get the full path and check if file exists
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            print(f"File not found at path: {file_path}")
            return jsonify({'message': 'File not found'}), 404

        # Send file with proper headers
        response = send_file(
            file_path,
            mimetype=None,  # Let Flask detect the MIME type
            as_attachment=False,
            download_name=filename,
            etag=True,
            conditional=True,
            last_modified=True
        )

        # Add necessary headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        
        print(f"Successfully serving file: {filename}")
        return response

    except Exception as e:
        print(f"Error serving file {filename}: {str(e)}")
        return jsonify({'message': 'Error serving file', 'error': str(e)}), 500

@app.route('/api/uploads/<path:filename>', methods=['OPTIONS'])
def serve_file_options(filename):
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
    return response

@app.route('/api/generate-receipt', methods=['POST'])
@jwt_required()
@moderate_rate_limit()
def generate_receipt():
    try:
        data = request.get_json()
        items = data.get('items', [])
        total = data.get('total', 0)
        
        if not items:
            return jsonify({'error': 'No items provided'}), 400

        # Create a unique filename for the PDF
        filename = f"receipt_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Create PDF with professional dimensions
        page_width = 2.8 * inch  # Standard receipt width
        page_height = 6.0 * inch  # Adjustable based on content
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=(page_width, page_height),
            rightMargin=0.1*inch,
            leftMargin=0.1*inch,
            topMargin=0.2*inch,
            bottomMargin=0.2*inch
        )

        # Prepare the story (content)
        story = []
        styles = getSampleStyleSheet()

        # Professional color scheme
        primary_color = colors.HexColor('#000000')  # Black for main text
        secondary_color = colors.HexColor('#666666')  # Gray for secondary text
        border_color = colors.HexColor('#CCCCCC')  # Light gray for borders

        # Header style - Clean and professional
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Normal'],
            fontSize=10,
            alignment=1,
            spaceAfter=2,
            textColor=primary_color,
            fontName='Helvetica-Bold'
        )

        # Subheader style
        subheader_style = ParagraphStyle(
            'Subheader',
            parent=styles['Normal'],
            fontSize=7,
            alignment=1,
            spaceAfter=2,
            textColor=secondary_color,
            fontName='Helvetica'
        )

        # Add header content
        story.append(Paragraph("KasirKuy", header_style))
        
        # Add date and time
        current_time = datetime.now()
        date_str = current_time.strftime('%d/%m/%Y %H:%M')
        story.append(Paragraph(date_str, subheader_style))

        # Add separator
        story.append(HRFlowable(
            width="100%",
            thickness=0.5,
            color=border_color,
            spaceBefore=4,
            spaceAfter=4
        ))

        # Function to format currency
        def format_currency(amount):
            return f"Rp {amount:,.0f}".replace(',', '.')

        # Table style - Clean and minimal
        table_style = TableStyle([
            # Headers
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('TEXTCOLOR', (0, 0), (-1, -1), primary_color),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),  # Left align first column
            ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),  # Right align other columns
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ])

        # Prepare table data
        table_data = []
        
        # Add items
        for item in items:
            name = item['name']
            if len(name) > 20:  # Limit name length
                name = name[:18] + '..'
            
            # Format: Item name with quantity and price
            qty_price = f"{item['quantity']} x {format_currency(item['price'])}"
            table_data.append([name, qty_price])

        # Create and style the table
        col_widths = [1.6*inch, 1.0*inch]  # Adjusted column widths
        table = Table(table_data, colWidths=col_widths)
        table.setStyle(table_style)
        story.append(table)

        # Add separator before total
        story.append(HRFlowable(
            width="100%",
            thickness=0.5,
            color=border_color,
            spaceBefore=6,
            spaceAfter=6
        ))

        # Add total with bold style
        total_style = TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TEXTCOLOR', (0, 0), (-1, -1), primary_color),
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ])

        total_table = Table([['Total', format_currency(total)]], colWidths=col_widths)
        total_table.setStyle(total_style)
        story.append(total_table)

        # Add separator before footer
        story.append(HRFlowable(
            width="100%",
            thickness=0.5,
            color=border_color,
            spaceBefore=6,
            spaceAfter=6
        ))

        # Footer style
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=6,
            alignment=1,
            textColor=secondary_color,
            fontName='Helvetica',
            spaceBefore=0,
            spaceAfter=2
        )

        # Add footer
        story.append(Paragraph("Terima kasih atas kunjungan Anda", footer_style))
        story.append(Paragraph("Sampai jumpa kembali", footer_style))

        # Build PDF
        doc.build(story)

        # Get the base URL from environment or default
        base_url = os.getenv('BASE_URL', request.url_root.rstrip('/'))
        pdf_url = f"{base_url}/api/uploads/{filename}"

        return jsonify({
            'message': 'Receipt generated successfully',
            'pdf_url': pdf_url
        }), 200

    except Exception as e:
        print(f"Error generating receipt: {str(e)}")
        return jsonify({'error': 'Failed to generate receipt'}), 500

# Admin routes
@app.route('/api/admin/users', methods=['GET'])
@admin_required()
@moderate_rate_limit()
def get_all_users():
    try:
        with get_db() as db:
            users = db.query(User).all()
            result = []
            
            for user in users:
                products = db.query(Product).filter(Product.user_id == user.id).all()
                result.append({
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'products_count': len(products)
                })
            
            return jsonify(result), 200
            
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return jsonify({'message': 'Failed to get users'}), 500

@app.route('/api/admin/users', methods=['POST'])
@admin_required()
@moderate_rate_limit()
def add_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        is_admin = data.get('is_admin', False)

        print(f"Adding new user: {username}, is_admin: {is_admin}")

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Check if username exists
        with get_db() as db:
            existing_user = db.query(User).filter(User.username == username).first()
            if existing_user:
                return jsonify({'message': 'Username already exists'}), 409

            # Create new user
            hashed_password = generate_password_hash(password, method=PASSWORD_HASH_METHOD)
            new_user = User(
                username=username,
                password=hashed_password,
                is_admin=is_admin
            )
            
            try:
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                
                return jsonify({
                    'id': new_user.id,
                    'username': new_user.username,
                    'is_admin': new_user.is_admin,
                    'created_at': new_user.created_at.isoformat() if new_user.created_at else None
                }), 201
                
            except Exception as e:
                db.rollback()
                print(f"Database error while creating user: {str(e)}")
                return jsonify({'message': 'Failed to create user'}), 500

    except Exception as e:
        print(f"Error adding user: {str(e)}")
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required()
@moderate_rate_limit()
def update_user(user_id):
    try:
        data = request.get_json()
        update_data = {}

        # Check if user exists
        user_response = get_user_by_id(user_id)
        if not user_response:
            return jsonify({'error': 'User not found'}), 404

        if 'username' in data:
            existing = get_user_by_username(data['username'])
            if existing and existing['id'] != user_id:
                return jsonify({'error': 'Username already exists'}), 409
            update_data['username'] = data['username']

        if 'password' in data and data['password']:
            update_data['password'] = generate_password_hash(data['password'], method=PASSWORD_HASH_METHOD)

        if 'is_admin' in data:
            update_data['is_admin'] = data['is_admin']

        if update_data:
            response = update_user(user_id, update_data)
            if not response:
                return jsonify({'error': 'Failed to update user'}), 500
            
            return jsonify(response), 200
        
        return jsonify({'message': 'No changes to update'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required()
@moderate_rate_limit()
def delete_user(user_id):
    try:
        print(f"Delete request for user ID: {user_id}")
        
        with get_db() as db:
            # Check if user exists
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({'message': 'User not found'}), 404

            # Don't allow deleting the last admin
            admin_count = db.query(User).filter(User.is_admin == True).count()
            if user.is_admin and admin_count <= 1:
                return jsonify({'message': 'Cannot delete the last admin user'}), 400

            # Delete all products for this user first
            products = db.query(Product).filter(Product.user_id == user_id).all()
            for product in products:
                if product.image_url:
                    # Delete product image if exists
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_url)
                    if os.path.exists(image_path):
                        os.remove(image_path)
                db.delete(product)

            # Delete the user
            db.delete(user)
            db.commit()

            return jsonify({'message': 'User deleted successfully'}), 200

    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return jsonify({'message': 'Failed to delete user'}), 500

@app.route('/api/admin/products', methods=['GET'])
@admin_required()
@moderate_rate_limit()
def get_all_products():
    try:
        with get_db() as db:
            products = db.query(Product).all()
            result = []
            
            for product in products:
                user = db.query(User).filter(User.id == product.user_id).first()
                result.append({
                    'id': product.id,
                    'name': product.name,
                    'price': product.price,
                    'image_url': product.image_url,
                    'user_id': product.user_id,
                    'created_at': product.created_at.isoformat() if product.created_at else None,
                    'user_name': user.username if user else None
                })
            
            return jsonify(result), 200
            
    except Exception as e:
        print(f"Error getting products: {str(e)}")
        return jsonify({'message': 'Failed to get products'}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@admin_required()
@moderate_rate_limit()
def admin_delete_product(product_id):
    try:
        print(f"Admin delete request for product ID: {product_id}")
        
        with get_db() as db:
            # Check if product exists
            product = db.query(Product).filter(Product.id == product_id).first()
            if not product:
                return jsonify({'message': 'Product not found'}), 404

            # Delete product image if exists
            if product.image_url:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_url)
                if os.path.exists(image_path):
                    os.remove(image_path)

            # Delete the product
            db.delete(product)
            db.commit()

            return jsonify({'message': 'Product deleted successfully'}), 200

    except Exception as e:
        print(f"Error deleting product: {str(e)}")
        return jsonify({'message': 'Failed to delete product'}), 500

# Add OPTIONS method handlers for CORS preflight requests
@app.route('/api/products/<string:product_id>', methods=['OPTIONS'])
def products_options(product_id):
    return '', 204

@app.route('/api/admin/products/<string:product_id>', methods=['OPTIONS'])
def admin_products_options(product_id):
    return '', 204

@app.route('/api/admin/users/<string:user_id>', methods=['OPTIONS'])
def admin_users_options(user_id):
    return '', 204

# Add request logging
@app.after_request
def after_request(response):
    if request.path.startswith('/api/'):
        print(
            f"[{datetime.now()}] {request.remote_addr} {request.method} "
            f"{request.path} {response.status_code}"
        )
    return response

# Add error logging
@app.errorhandler(Exception)
def handle_error(error):
    print(f"Error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# Add this function near the other helper functions
def cleanup_old_images():
    """Clean up unused images from the upload folder"""
    try:
        # Get all products with images
        response = get_products_by_user(0)
        active_images = set()
        
        # Collect all active image filenames
        if response:
            for product in response:
                if product.get('image_url'):
                    filename = product['image_url'].split('/')[-1]
                    active_images.add(filename)
        
        # Check upload folder and remove receipt files and truly orphaned images
        current_time = time.time()
        for filename in os.listdir(UPLOAD_FOLDER):
            # Skip non-files
            if not os.path.isfile(os.path.join(UPLOAD_FOLDER, filename)):
                continue
                
            file_path = os.path.join(UPLOAD_FOLDER, filename)
                
            # Clean up receipt files that are older than 5 minutes
            if filename.startswith('receipt_'):
                try:
                    file_age = current_time - os.path.getmtime(file_path)
                    if file_age > 300:  # 5 minutes in seconds
                        os.remove(file_path)
                        print(f"Cleaned up old receipt file: {filename}")
                except Exception as e:
                    print(f"Error deleting receipt file {filename}: {str(e)}")
                continue
            
            # Only delete image files that are not referenced by any product
            if allowed_file(filename) and filename not in active_images:
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                try:
                    # Double check if image is truly not referenced
                    double_check = get_products_by_user(0)
                    if not double_check:
                        os.remove(file_path)
                        print(f"Cleaned up unused image: {filename}")
                except Exception as e:
                    print(f"Error deleting file {filename}: {str(e)}")
    except Exception as e:
        print(f"Error during image cleanup: {str(e)}")

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        response = jsonify({'message': 'Successfully logged out'})
        
        # Clear the JWT cookie
        response.delete_cookie(
            AUTH_COOKIE_NAME,
            path=app.config['JWT_ACCESS_COOKIE_PATH'],
            domain=None,
            secure=app.config['JWT_COOKIE_SECURE'],
            samesite=app.config['JWT_COOKIE_SAMESITE']
        )
        
        print("Logout successful - Cookie cleared")  # Debug log
        return response
        
    except Exception as e:
        print(f"Logout error: {str(e)}")  # Debug log
        return jsonify({'message': 'An error occurred during logout'}), 500

# Add OPTIONS route handlers for auth endpoints
@app.route('/api/login', methods=['OPTIONS'])
def login_options():
    return '', 204

@app.route('/api/register', methods=['OPTIONS'])
def register_options():
    return '', 204

@app.after_request
def after_request(response):
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept, Origin, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '600'
    return response

# Add a general OPTIONS handler for all routes
@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return '', 204

# Add root route handler
@app.route('/')
def root():
    return jsonify({
        'status': 'healthy',
        'message': 'KasirKuy API is running'
    }), 200

# Update error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

# Add verify endpoint
@app.route('/api/verify', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        # Get current user ID from JWT and convert to int
        current_user_id = int(get_jwt_identity())
        
        # Get user data
        user = get_user_by_id(current_user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Return user data without sensitive information
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin']
        })
        
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        return jsonify({'message': 'Invalid token'}), 401

# Helper function to save uploaded file
def save_file(file):
    """
    Save an uploaded file with proper validation and error handling
    """
    try:
        # Validate file object
        if not file or not isinstance(file, FileStorage):
            print("Invalid file object provided")
            return None

        # Validate filename
        if not file.filename:
            print("No filename provided")
            return None

        # Secure the filename and validate
        filename = secure_filename(file.filename)
        if not filename:
            print("Invalid filename after securing")
            return None

        # Validate file extension
        file_extension = os.path.splitext(filename)[1].lower()
        if file_extension not in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            print(f"Invalid file extension: {file_extension}")
            return None

        # Ensure upload directory exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            print(f"Creating upload directory: {app.config['UPLOAD_FOLDER']}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # Generate unique filename
        unique_filename = f"{uuid.uuid4().hex}{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            # Save the file
            file.save(file_path)
            print(f"File saved successfully at: {file_path}")
            
            # Verify file was saved
            if not os.path.exists(file_path):
                print("File was not saved successfully")
                return None
                
            return unique_filename

        except Exception as e:
            print(f"Error saving file content: {str(e)}")
            # Clean up if file was partially saved
            if os.path.exists(file_path):
                os.remove(file_path)
            return None

    except Exception as e:
        print(f"Error in save_file: {str(e)}")
        return None

if __name__ == '__main__':
    # Create default admin user if none exists
    try:
        admin_user = get_user_by_username('wildanhniif')
        if not admin_user:
            response = create_user('wildanhniif', 'pemenang321', is_admin=True)
            if response:
                print("Default admin user created - Username: wildanhniif, Password: pemenang321")
            else:
                print("Failed to create default admin user")
    except Exception as e:
        print(f"Error creating default admin: {str(e)}")
            
    app.run(debug=True) 