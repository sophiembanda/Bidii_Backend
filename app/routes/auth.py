import logging
from flask import Blueprint, current_app, request, jsonify, url_for
from flask_cors import cross_origin
from app.models import User
from flask_mail import Message, Mail
from app.extensions import mail, db
from app.schemas import UserSchema
from app.services.auth_service import AuthService
from sqlalchemy.exc import IntegrityError, NoResultFound
from app.services.auth_service import admin_required
from flask_jwt_extended import jwt_required, get_jwt_identity, unset_jwt_cookies

from app.utils.helpers import hash_password

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
bp = Blueprint('auth', __name__)

@bp.route('/signup', methods=['POST'])
@cross_origin()
# @admin_required
def signup():
    try:
        data = request.get_json()

        # Debug statement for incoming data
        logger.debug(f"Received data: {data}")
        user = AuthService.create_user(data)
        user_schema = UserSchema()
        result = user_schema.dump(user)
        if user:
            # return jsonify({'message': 'User created successfully.'}), 201
            return jsonify(result), 201
        return jsonify({'message': 'Failed to create user.'}), 400
    except IntegrityError as e:
        db.session.rollback()  # Rollback the session to prevent partially committed data
        return jsonify({'message': 'Username or email already exists', 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to create user', 'error': str(e)}), 500
    
@bp.route('/signin', methods=['POST'])
@cross_origin()
def signin():
    try:
        data = request.get_json()
        user, token = AuthService.authenticate_user(data)
        if user:
            return jsonify({'user': UserSchema().dump(user), 'token': token}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except NoResultFound:
        return jsonify({'message': 'User not found'}), 401
    except ValueError as e:
        return jsonify({'message': str(e)}), 401
    except Exception as e:
        return jsonify({'message': 'Failed to sign in', 'error': str(e)}), 500

@bp.route('/user_info', methods=['GET'])
@jwt_required()
@cross_origin()
def get_user_info():
    try:
        # Retrieve the user identity from the JWT token
        current_user_identity = get_jwt_identity()
        
        # Fetch the user from the database using the user ID or another identifier
        user_id = current_user_identity.get('id')
        user = db.session.get(User, user_id)
        
        if user:
            user_schema = UserSchema()  # Adjust this if you have a specific schema for user data
            result = user_schema.dump(user)
            return jsonify(result), 200
        else:
            return jsonify({'message': 'User not found.'}), 404

    except Exception as e:
        return jsonify({'message': 'Failed to retrieve user information', 'error': str(e)}), 500

    
@bp.route('/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email address not found'}), 404

    try:
        token = AuthService.generate_password_reset_token(email)
        reset_url = url_for('auth.reset_password', token=token, _external=True)
        
        msg = Message('Password Reset Request',
                      recipients=[email],
                      body=f'Please use the following link to reset your password: {reset_url}')
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'message': 'Failed to request password reset', 'error': str(e)}), 500

    return jsonify({'message': 'Password reset email sent', 'token': token}), 200

@bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        data = request.get_json()
        new_password = data.get('new_password')

        email = AuthService.verify_password_reset_token(token)
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password_hash = hash_password(new_password)
                db.session.commit()
                return jsonify({'message': 'Password has been reset successfully.'}), 200
            else:
                return jsonify({'message': 'User not found.'}), 404
        else:
            return jsonify({'message': 'Invalid or expired token.'}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to reset password', 'error': str(e)}), 500
    
@bp.route('/logout', methods=['POST'])
@jwt_required()
@cross_origin()
def logout():
    try:
        response = jsonify({"message": "Successfully logged out"})
        unset_jwt_cookies(response)  # This function unsets the JWT cookies
        return response, 200
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        return jsonify({"message": "Failed to log out", "error": str(e)}), 500