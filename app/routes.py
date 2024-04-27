from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .models import User
from . import db

main = Blueprint('main', __name__)

@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    quote = data['quote']
    if User.query.filter_by(username=username).first():
        return jsonify(message="User already exists"), 409
    password_hash = generate_password_hash(password)
    new_user = User(username=username, password_hash=password_hash, favorite_quote=quote)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User created"), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        token = create_access_token(identity=user.username)
        return jsonify(token=token), 200
    else:
        return jsonify(message="Invalid credentials"), 401

@main.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    return jsonify(username=user.username, quote=user.favorite_quote)
