from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import json

# Initialize the SQLAlchemy extension
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False) # 'farmer', 'distributor', 'retailer'
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    transactions = db.relationship('Transaction', backref='actor', lazy=True)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    farmer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    harvest_date = db.Column(db.DateTime, nullable=False)
    organic_certification_id = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)

    farmer = db.relationship('User', backref='products_created')
    transactions = db.relationship('Transaction', backref='product', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Product {self.id}: {self.product_name}>'

class Block(db.Model):
    __tablename__ = 'blocks'
    id = db.Column(db.Integer, primary_key=True)
    previous_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # ** BUG FIX IS HERE **
    nonce = db.Column(db.Integer, default=0, nullable=False)

    transactions = db.relationship('Transaction', backref='block', lazy=True)

    def compute_hash(self):
        """Computes the hash of the entire block."""
        block_string = json.dumps({
            "id": self.id,
            "previous_hash": self.previous_hash,
            "timestamp": str(self.timestamp),
            "nonce": self.nonce,
            "transactions": [t.to_dict() for t in self.transactions]
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def __repr__(self):
        return f'<Block {self.id}>'

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    block_id = db.Column(db.Integer, db.ForeignKey('blocks.id'), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Returns a dictionary representation of the transaction for hashing."""
        return {
            'id': self.id,
            'product_id': self.product_id,
            'actor_id': self.actor_id,
            'action': self.action,
            'timestamp': str(self.timestamp),
            'organic_certification_id': self.product.organic_certification_id if self.product else None
        }

    def __repr__(self):
        return f'<Transaction {self.id} for Product {self.product_id}>'

