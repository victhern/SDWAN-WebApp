from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db, login_manager


class Permission:
    MAP_MONITORING = 1
    NOTICE_CENTER = 2
    ADMIN_VIEW = 4
    ADD_DEVICES = 8
    CREATE_NETWORK = 16
    REPLACE_DEVICES = 32
    UPDATE_SSID = 64
    BULK_CHANGE = 128
    DC_SWITCHOVER = 256
    LOAD_BALANCING = 512
    APP_SETTINGS = 1024
    ADMIN_MANAGE = 2048
    ORG_UPDATE = 4096



class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            'Monitor': [Permission.MAP_MONITORING, Permission.NOTICE_CENTER, Permission.ADMIN_VIEW],
            'Field': [Permission.MAP_MONITORING, Permission.NOTICE_CENTER, Permission.ADMIN_VIEW,
                      Permission.ADD_DEVICES, Permission.CREATE_NETWORK, Permission.REPLACE_DEVICES,
                      Permission.UPDATE_SSID],
            'Privileged': [Permission.MAP_MONITORING, Permission.NOTICE_CENTER, Permission.ADMIN_VIEW,
                      Permission.ADD_DEVICES, Permission.CREATE_NETWORK, Permission.REPLACE_DEVICES,
                      Permission.UPDATE_SSID, Permission.BULK_CHANGE, Permission.DC_SWITCHOVER],
            'Administrator': [Permission.MAP_MONITORING, Permission.NOTICE_CENTER, Permission.ADMIN_VIEW,
                      Permission.ADD_DEVICES, Permission.CREATE_NETWORK, Permission.REPLACE_DEVICES,
                      Permission.UPDATE_SSID, Permission.BULK_CHANGE, Permission.DC_SWITCHOVER, 
                      Permission.APP_SETTINGS, Permission.ADMIN_MANAGE, Permission.ORG_UPDATE]
        }
        default_role = 'Monitor'

        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    full_name = db.Column(db.String(64), index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['ADMIN_MAIL']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.APP_SETTINGS)

    @staticmethod
    def insert_admin_user():
        admin_user = User(email=current_app.config['ADMIN_MAIL'], username=current_app.config['ADMIN_MAIL'],
                          password=current_app.config['ADMIN_PASSWORD'], full_name=current_app.config['ADMIN_NAME'])

        db.session.add(admin_user)
        db.session.commit()

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
