from flask_login import UserMixin
from werkzeug.security import generate_password_hash
import json
import os

USERS_FILE = 'users.json'

class User(UserMixin):
    def __init__(self, id, username, password, role='user'):
        self.id = str(id)
        self.username = username
        self.password = password
        self.role = role  # 'admin', 'user', 'read_only'

    @staticmethod
    def get_by_username(username):
        users = User.load_users()
        for user in users:
            if user['username'] == username:
                return User(
                    user['id'],
                    user['username'],
                    user['password'],
                    user.get('role', 'user')  # fallback für alte Nutzer
                )
        return None

    @staticmethod
    def get_all():
        users = User.load_users()
        return [
            User(u['id'], u['username'], u['password'], u.get('role', 'user'))
            for u in users
        ]

    @staticmethod
    def load_users():
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        return []

    @staticmethod
    def load_by_id(user_id):
        users = User.load_users()
        for user in users:
            if str(user['id']) == str(user_id):
                return User(user['id'], user['username'], user['password'], user.get('role', 'user'))
        return None


    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_readonly(self):
        return self.role == 'readonly'

    VALID_ROLES = {'admin', 'user', 'readonly'}

    @staticmethod
    def save_user(username, raw_password, role='user'):
        users = User.load_users()
        user_id = str(len(users) + 1)
        hashed_pw = generate_password_hash(raw_password)
        users.append({
            'id': user_id,
            'username': username,
            'password': hashed_pw,
            'role': role
        })
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)

def load_user(user_id):
    users = User.load_users()
    for user in users:
        if str(user['id']) == str(user_id):
            return User(
                user['id'],
                user['username'],
                user['password'],
                user.get('role', 'user')
            )
    return None
