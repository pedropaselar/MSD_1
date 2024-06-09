from flask import Flask, request, jsonify
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User
import logging

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

# Configuração de logging
logging.basicConfig(filename='error.log', level=logging.DEBUG)

@app.route('/', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        app.logger.debug(f"Data received: {data}")
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            app.logger.error("Username or password not provided")
            return jsonify({"message": "Username and password are required"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 400
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        app.logger.error(f"Error creating user: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/', methods=['PUT'])
def login_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"message": "Invalid username or password"}), 401
        if user.blocked:
            return jsonify({"message": "User is blocked"}), 403
        if not check_password_hash(user.password, password):
            user.total_failures += 1
            if user.total_failures > 5:
                user.blocked = True
            db.session.commit()
            return jsonify({"message": "Invalid username or password"}), 401
        user.total_logins += 1
        if user.total_logins > 10:
            return jsonify({"message": "Password change required"}), 403
        db.session.commit()
        return jsonify({"message": "Login successful"}), 200
    except Exception as e:
        app.logger.error(f"Error logging in user: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/trocasenha', methods=['PUT'])
def change_password():
    try:
        data = request.get_json()
        username = data.get('username')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, current_password):
            return jsonify({"message": "Invalid username or password"}), 401
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.total_logins = 0
        db.session.commit()
        return jsonify({"message": "Password changed successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error changing password: {e}")
        return jsonify({"message": "Internal server error"}), 500

@app.route('/bloqueados', methods=['GET'])
def get_blocked_users():
    try:
        blocked_users = User.query.filter_by(blocked=True).all()
        result = []
        for user in blocked_users:
            user_data = {'username': user.username, 'total_failures': user.total_failures}
            result.append(user_data)
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error fetching blocked users: {e}")
        return jsonify({"message": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
