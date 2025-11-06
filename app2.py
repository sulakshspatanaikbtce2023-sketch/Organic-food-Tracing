from flask import Flask, render_template, request, redirect, url_for, flash, session
from Models2 import db, User, Product, Block, Transaction
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import joinedload

# --- App Initialization ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///organic_food.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'My_Secret_Key'

db.init_app(app)

# --- Blockchain Core Helper Functions ---

DIFFICULTY = "00"

def create_genesis_block():
    if not Block.query.first():
        genesis_block = Block(previous_hash='0' * 64, nonce=0)
        mined_block = mine_block(genesis_block)
        db.session.add(mined_block)
        db.session.commit()
        print("Genesis Block Created!")

def mine_block(block):
    while not block.compute_hash().startswith(DIFFICULTY):
        block.nonce += 1
    return block

def add_transaction_to_new_block(transaction):
    last_block = Block.query.order_by(Block.id.desc()).first()
    if not last_block:
        create_genesis_block()
        last_block = Block.query.order_by(Block.id.desc()).first()

    last_hash = last_block.compute_hash()
    
    # ** THE DEFINITIVE FIX IS HERE **
    # We explicitly initialize nonce=0 on the Python object.
    new_block = Block(previous_hash=last_hash, nonce=0)
    
    new_block.transactions.append(transaction)
    
    mined_block = mine_block(new_block)
    
    db.session.add(mined_block)
    db.session.commit()

# --- Database and App Context Setup ---
with app.app_context():
    if not os.path.exists('organic_food.db'):
        db.create_all()
        create_genesis_block()

# --- Decorators for Access Control ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role_name:
                flash(f'You must be a {role_name} to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- User Authentication Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, email, password, role = request.form['username'], request.form['email'], request.form['password'], request.form['role']
        if User.query.filter_by(email=email).first():
            flash('Email address already exists.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'], session['username'], session['role'] = user.id, user.username, user.role
            flash('You have successfully logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('index'))

# --- Main Dashboard ---

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    user_id = session.get('user_id')

    if role == 'farmer':
        products = Product.query.filter_by(farmer_id=user_id).order_by(Product.id.desc()).all()
        distributors = User.query.filter_by(role='distributor').all()
        return render_template('farmer_dashboard.html', products=products, distributors=distributors)
    
    elif role == 'distributor':
        transactions = Transaction.query.filter_by(action='SHIPPED_TO_DISTRIBUTOR', actor_id=user_id).all()
        product_ids = [t.product_id for t in transactions]
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        retailers = User.query.filter_by(role='retailer').all()
        return render_template('distributor_dashboard.html', products=products, retailers=retailers)

    elif role == 'retailer':
        transactions = Transaction.query.filter_by(action='DELIVERED_TO_RETAILER', actor_id=user_id).all()
        product_ids = [t.product_id for t in transactions]
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        return render_template('retailer_dashboard.html', products=products)
    
    return redirect(url_for('logout'))

# --- Farmer Specific Routes ---

@app.route('/add_product', methods=['POST'])
@login_required
@role_required('farmer')
def add_product():
    new_product = Product(
        product_name=request.form['product_name'],
        organic_certification_id=request.form['organic_certification_id'],
        harvest_date=datetime.strptime(request.form['harvest_date'], '%Y-%m-%d'),
        farmer_id=session['user_id']
    )
    db.session.add(new_product)
    db.session.commit()

    transaction = Transaction(
        product_id=new_product.id,
        actor_id=session['user_id'],
        action='CREATED',
        details=request.form['details']
    )
    add_transaction_to_new_block(transaction)
    
    flash('New product has been registered on the blockchain.', 'success')
    return redirect(url_for('dashboard'))

# --- (Rest of the file is the same) ---

@app.route('/transfer_product/<int:product_id>', methods=['POST'])
@login_required
@role_required('farmer')
def transfer_product(product_id):
    distributor_id = request.form['distributor_id']
    distributor = User.query.get(distributor_id)
    
    transaction = Transaction(
        product_id=product_id,
        actor_id=int(distributor_id),
        action='SHIPPED_TO_DISTRIBUTOR',
        details=f"Shipped by {session['username']} to {distributor.username}"
    )
    add_transaction_to_new_block(transaction)

    flash(f'Product {product_id} shipped to distributor {distributor.username}.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/update_status/<int:product_id>', methods=['POST'])
@login_required
@role_required('distributor')
def update_status(product_id):
    retailer_id = request.form['retailer_id']
    retailer = User.query.get(retailer_id)
    
    transaction = Transaction(
        product_id=product_id,
        actor_id=int(retailer_id),
        action='DELIVERED_TO_RETAILER',
        details=f"Delivered by {session['username']} to {retailer.username}"
    )
    add_transaction_to_new_block(transaction)

    flash(f'Product {product_id} marked as delivered to {retailer.username}.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/confirm_receipt/<int:product_id>', methods=['POST'])
@login_required
@role_required('retailer')
def confirm_receipt(product_id):
    transaction = Transaction(
        product_id=product_id,
        actor_id=session['user_id'],
        action='RECEIVED_BY_RETAILER',
        details="Product available for sale."
    )
    add_transaction_to_new_block(transaction)

    flash(f'Receipt of product {product_id} confirmed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/trace', methods=['GET', 'POST'])
def trace():
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        if product_id:
            if Product.query.get(product_id):
                return redirect(url_for('trace_result', product_id=product_id))
            else:
                flash('Product ID not found. Please check the ID and try again.', 'danger')
        else:
            flash('Please enter a Product ID.', 'warning')
    return render_template('trace.html')

@app.route('/trace/<int:product_id>')
def trace_result(product_id):
    product = Product.query.get_or_404(product_id)
    transactions = Transaction.query.options(joinedload(Transaction.actor)).filter_by(product_id=product_id).order_by(Transaction.timestamp.asc()).all()
    return render_template('trace_result.html', product=product, transactions=transactions)

@app.route('/verify_chain')
@login_required
def verify_chain():
    blocks = Block.query.order_by(Block.id.asc()).all()
    results = []
    is_valid = True
    for i in range(1, len(blocks)):
        current_block = blocks[i]
        previous_block = blocks[i-1]
        
        actual_previous_hash = previous_block.compute_hash()
        stored_previous_hash = current_block.previous_hash

        block_is_valid = actual_previous_hash == stored_previous_hash
        
        results.append({
            'block_id': current_block.id,
            'is_valid': block_is_valid,
            'stored_hash': stored_previous_hash,
            'actual_hash': actual_previous_hash
        })
        
        if not block_is_valid:
            is_valid = False
            
    return render_template('verify_chain.html', results=results, is_valid=is_valid)

if __name__ == '__main__':
    app.run(debug=True)

