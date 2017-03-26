from functools import wraps
from flask import abort
from flask.ext.login import current_user

def permission_required(admin):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if admin:
                if not current_user.isadmin():
                    abort(403)
                return f(*args, **kwargs)
            else:
                if current_user.isadmin():
                    abort(403)
                return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(True)(f)

def normal_required(f):
    return permission_required(False)(f)