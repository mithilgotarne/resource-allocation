from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import and_
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    rl_user = db.relationship('RequestLog', backref='rl_user', lazy='dynamic')
    
    def set_role(self, role):
        self.role_id = role

    def can(self, resource, action):
        temp_role = Role.query.filter_by(id = self.role_id).first()
        for res in temp_role.myresources:
            if res.assigned_resource == resource and (res.actions & action) == action:
                return True
        return False
    
    def get_access(self, resource, reason):
        has_access = "Pending"
        if self.can(resource, ActionType.ACCESS):
            has_access = "Granted"
            resource.decrement()
        temp_log = RequestLog(rl_user=self, rl_res=resource, timestamp=datetime.now(), reason=reason, status=has_access)
        db.session.add(temp_log)
        db.session.commit()
    
    def release_access(self, resource):
        rlog = RequestLog.query.filter(and_(RequestLog.res_id==resource.id, RequestLog.user_id == self.id)).first()
        rlog.status = "Returned"
        res = Resource.query.filter_by(id=rlog.res_id).first()
        res.increment()
        db.session.commit()
    
    def approve_resource(self, resource, requester):
        if self.can(resource, ActionType.GRANT):
            if self.role_id > requester.role_id:
                rlog = RequestLog.query.filter(and_(RequestLog.res_id==resource.id, RequestLog.status=="Pending", RequestLog.user_id == requester.id )).first()
                rlog.status = "Granted"
                db.session.commit()

    def __repr__(self):
        return '<User %r>' % (self.name)


class RoleResourceMap(db.Model):
    __tablename__ = 'roleresourcemap'
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    resource_id = db.Column(db.String, db.ForeignKey('resources.id'))
    actions = db.Column(db.Integer)
    assigned_resource = db.relationship(
        'Resource', backref=db.backref('resources'))
    

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    myresources = db.relationship('RoleResourceMap', backref=db.backref(
        'resources'))
    users = db.relationship('User', backref='user_role', lazy='dynamic') 

    def change_resource_map(self, resource, actions):
        if not self.has_resource(resource):
            rr_item = RoleResourceMap(assigned_resource=resource, actions=actions)
            self.myresources.append(rr_item)
        else:
            rr_item = RoleResourceMap.query.filter(and_(RoleResourceMap.resource_id == resource.id,
                                                        RoleResourceMap.role_id == self.id)).first()
            rr_item.actions = actions
        db.session.commit()

    def has_resource(self, resource):
        return RoleResourceMap.query.filter(and_(RoleResourceMap.resource_id == resource.id,
                                                 RoleResourceMap.role_id == self.id)).first() is not None

    def can(self, resource, action):
        for res in self.myresources:
            if res.assigned_resource == resource and (res.actions & action) == action:
                return True
        return False
    
    @staticmethod
    def insert_roles():
        def_roles = ['Student', 'Teacher', 'HOD']
        for r in def_roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
                db.session.add(role)
                db.session.commit()

    def __repr__(self):
        return '<Role %r>' % (self.name)


class ActionType:
    ACCESS = 0x01
    GRANT = 0x02
    MODIFY = 0x04


class Resource(db.Model):
    __tablename__ = 'resources'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    quantity = db.Column(db.Integer, default=0)
    rl_res = db.relationship('RequestLog', backref='rl_res', lazy='dynamic')
    
    def decrement(self):
        if self.in_stock():
            self.quantity -= 1
    
    def increment(self):
        self.quantity += 1

    def in_stock(self):
        return self.quantity > 0
    
    def __repr__(self):
        return '<Resource %r>' % (self.name)

class RequestLog(db.Model):
    __tablename__ = 'request_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    res_id = db.Column(db.Integer, db.ForeignKey('resources.id'))
    reason = db.Column(db.String(64))
    timestamp = db.Column(db.Integer)
    status = db.Column(db.String)

    def __repr__(self):
        return '<Request %r>' % (self.reason)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))