from app import app, db
from flask import render_template, flash, redirect, url_for, request, g, jsonify
from flask_login import login_required, current_user, logout_user, login_user
from .forms import *
from .models import *
from .decorators import *

selected_roles = list()


@app.route('/')
@app.route('/index', methods=['GET', 'POST'])
def index():
    if not g.user.is_authenticated:
        return redirect(url_for('login'))
    if g.user.name=="admin":
        return redirect(url_for('allrequests'))
    else:
        return redirect(url_for('access'))

@app.route('/myrequests', methods=['GET', 'POST'])
@login_required
@normal_required
def myrequests():
    rlog_all = RequestLog.query.filter_by(user_id=g.user.id).all()
    res = list()
    timestamp = list()
    reason = list()
    status = list()
    count = len(rlog_all)

    for i in rlog_all:
        res.append(Resource.query.filter_by(id=i.res_id).first())
        timestamp.append(i.timestamp)
        reason.append(i.reason)
        status.append(i.status)

    return render_template('myrequests.html', res=res, timestamp=timestamp, reason=reason, status=status, count=count)

@app.route('/pendingrequests', methods=['GET', 'POST'])
@login_required
@normal_required
def pendingrequests():
    rlog_all = RequestLog.query.filter_by(status="Pending").all()
    users = list()
    res = list()
    timestamp = list()
    reason = list()

    for i in rlog_all:
        temp_user = User.query.filter_by(id = i.user_id).first()
        temp_res = Resource.query.filter_by(id = i.res_id).first() 
        if temp_user.role_id < g.user.role_id and g.user.can(temp_res, ActionType.GRANT):
            users.append(temp_user)
            res.append(temp_res)
            timestamp.append(i.timestamp)
            reason.append(i.reason)

    return render_template('pendingrequests.html', res=res, timestamp=timestamp, reason=reason, users=users, count=len(reason))


@app.route('/access', methods=['GET', 'POST'])
@login_required
@normal_required
def access():
    form = AccessForm()
    form.resources.choices = [(str(x.id), x.name) for x in Resource.query.all()]
    if form.validate_on_submit():
        myres = Resource.query.filter_by(id=int(form.resources.data)).first()
        g.req_status = g.user.get_access(myres, form.reason.data)
    return render_template('access.html', form = form)

@app.route('/retresource/<resid>', methods=['GET', 'POST'])
@login_required
@normal_required
def retresource(resid):
    resid = int(resid)
    tempr = Resource.query.filter_by(id=resid).first()
    if tempr is not None:
        g.user.release_access(tempr)
        db.session.commit()
    return redirect(url_for("myrequests"))


@app.route('/declineresource/<int:resid>/<int:userid>', methods=['GET', 'POST'])
@login_required
@normal_required
def declineresource(resid, userid):
    resid = int(resid)
    userid = int(userid)
    tempr = Resource.query.filter_by(id=resid).first()
    tempu = User.query.filter_by(id=userid).first()
    if tempr is not None and tempu is not None:
        g.user.deny_resource(tempr, tempu)
        db.session.commit()
    return redirect(url_for("pendingrequests"))


@app.route('/approveresource/<int:resid>/<int:userid>', methods=['GET', 'POST'])
@login_required
@normal_required
def approveresource(resid, userid):
    resid = int(resid)
    userid = int(userid)
    tempr = Resource.query.filter_by(id=resid).first()
    tempu = User.query.filter_by(id=userid).first()
    if tempr is not None and tempu is not None:
        g.user.approve_resource(tempr, tempu)
        db.session.commit()
    return redirect(url_for("pendingrequests"))

@app.route('/allrequests')
@login_required
@admin_required
def allrequests():
    rlog_all = RequestLog.query.all()
    res = list()
    roles = list()
    users = list()
    timestamp = list()
    reason = list()
    status = list()
    count = len(rlog_all)

    for i in rlog_all:
        cur_user = User.query.filter_by(id=i.user_id).first()
        res.append(Resource.query.filter_by(id=i.res_id).first().name)
        roles.append(Role.query.filter_by(id=cur_user.role_id).first().name)
        users.append(cur_user.name)
        timestamp.append(i.timestamp)
        reason.append(i.reason)
        status.append(i.status)

    return render_template('allrequests.html', users=users, res=res, timestamp=timestamp, reason=reason, status=status, count=count, roles=roles)

# Users
@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    users = User.query.all()
    all_roles = Role.query.all()
    return render_template('users.html', title="Users", users=users, allroles=all_roles)


@app.route('/newuser', methods=['GET', 'POST'])
def newuser():
    form = NewUserForm()
    g.myerror = ""
    if form.validate_on_submit():
        temp = Role.query.filter_by(id=int(form.role.data)).first()
        u = User(name=form.name.data, email=form.email.data)
        u.password = form.password.data
        checkuser = User.query.filter_by(email=form.email.data).first()
        if checkuser is None:
            #db.session.commit()
            u.set_role(temp)
            db.session.add(u)
            db.session.commit()
            if g.user.is_authenticated and g.user.isadmin():
                return redirect(url_for('users'))
            else:
                return redirect(url_for('login'))
        else:
            g.myerror = "This user already exists"
    return render_template('newuser.html', form=form)


@app.route('/deleteuser/<userid>', methods=['GET', 'POST'])
@login_required
def deleteuser(userid):
    userid = int(userid)
    cur_user = User.query.filter_by(id=userid).first()
    if cur_user is not None:
        db.session.delete(cur_user)
        db.session.commit()
    return redirect(url_for("users"))


# Resources
@app.route('/resources', methods=['GET', 'POST'])
def resources():
    all_resources = Resource.query.all()
    return render_template('resources.html', title="Resources", all_resources=all_resources)


@app.route('/addresource', methods=['GET', 'POST'])
def addresource():
    form = ResourceForm()
    g.myerror = ""
    if form.validate_on_submit():
        r = Resource(name=form.name.data, quantity=form.quantity.data)
        db.session.add(r)
        db.session.commit()
        return redirect(url_for('resources'))
    return render_template('addresource.html', title="Add Resource", form=form, isedit=False, res=None)


@app.route('/editresource/<resid>', methods=['GET', 'POST'])
def editresource(resid):
    form = ResourceForm()
    resid = int(resid)
    cur_res = Resource.query.filter_by(id=resid).first()
    if cur_res is None:
        return render_template('cust_error.html', title='Resource Not Found', msg="Resource you are looking for does not exist")
    else:
        if form.validate_on_submit():
            cur_res.name = form.name.data
            cur_res.quantity = form.quantity.data
            db.session.commit()
            return redirect(url_for('resources'))
        return render_template('addresource.html', title="Edit Resource", form=form, isedit=True, res=cur_res)


@app.route('/deleteresource/<resid>', methods=['GET', 'POST'])
def deleteresource(resid):
    resid = int(resid)
    cur_res = Resource.query.filter_by(id=resid).first()
    if cur_res is not None:
        db.session.delete(cur_res)
        db.session.commit()
    return redirect(url_for("resources"))


# Role
@app.route('/roles', methods=['GET', 'POST'])
def roles():
    all_roles = Role.query.all()
    all_res = Resource.query.all()

    return render_template('roles.html', title="Roles", all_roles=all_roles, all_res=all_res)

@app.route('/editrole/<roleid>', methods=['GET', 'POST'])
def editrole(roleid):
    form = RoleForm()
    g.myerror = ""
    roleid = int(roleid)
    cur_role = Role.query.filter_by(id=roleid).first()

    if cur_role is None:
        return render_template('cust_error.html', title='Role Not Found' , msg="Role you are looking for does not exist")
    else:
        all_res = Resource.query.all()
        form.access_resources.choices = [(str(x.id), str(ActionType.ACCESS)) for x in all_res]
        form.grant_resources.choices = [(str(x.id), str(ActionType.GRANT)) for x in all_res]
        form.modify_resources.choices = [(str(x.id), str(ActionType.MODIFY)) for x in all_res]
        
        if form.validate_on_submit():
            my_res_act_map = dict()
            for res in all_res:
                my_res_act_map[res] = 0

            for chk in form.access_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.ACCESS
            for chk in form.grant_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.GRANT

            for chk in form.modify_resources:
                if chk.checked:
                    tmp = Resource.query.filter_by(id=int(chk.data)).first()
                    my_res_act_map[tmp] |= ActionType.MODIFY

            for res in my_res_act_map:
                cur_role.change_resource_map(res, my_res_act_map[res])

            db.session.commit()
            return redirect(url_for('roles'))
    return render_template('addrole.html', title="Add Role", form=form, isedit=True, all_res=all_res, role=cur_role)


@app.route('/deleterole/<roleid>', methods=['GET', 'POST'])
def deleterole(roleid):
    roleid = int(roleid)
    cur_role = Role.query.filter_by(id=roleid).first()
    if cur_role is not None:
        db.session.delete(cur_role)
        db.session.commit()
    return redirect(url_for("roles"))


@app.errorhandler(404)
def not_found_error(error):
    return render_template('cust_error.html', title='404 Not Found', msg='404 Not Found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html', title='500 Server Error', msg='500 Server Error'), 500


@app.errorhandler(400)
def internal_error(error):
    db.session.rollback()
    return render_template('400.html', title='400 Error', msg='400 Server Error'), 400


@app.before_request
def before_request():
    g.user = current_user

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    g.myerror = "";
    if g.user is not None and g.user.is_authenticated:
        return redirect(url_for('index'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        else:
            g.myerror = 'Invalid email or password.'
            flash('Invalid username or password.')
    return render_template('login.html', form=form)
