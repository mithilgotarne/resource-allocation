from flask_wtf import Form
from wtforms import StringField, BooleanField
from wtforms.fields import SelectMultipleField, HiddenField, PasswordField, IntegerField, SelectField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import Length, Email, InputRequired, EqualTo
from wtforms import widgets


class MultiCheckboxField(SelectMultipleField):
    """
    A multiple-select, except displays a list of checkboxes.

    Iterating the field will produce subfields, allowing custom rendering of
    the enclosed checkbox fields.

    http://wtforms.readthedocs.io/en/1.0.4/specific_problems.html#specialty-field-tricks
    """
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class RegistrationForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])
    email = EmailField('email', validators=[Email(), InputRequired(message='Email field cannot be left blank')])
    password = PasswordField('New Password', validators=[InputRequired(message='Password field cannot be left blank'),
                                                         EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password',
                            validators=[InputRequired(message='Confirm Password field cannot be left blank')])
    role = SelectField('role', choices=[(1, 'Student'), (2, 'Teacher'), (3, 'HOD')],
                         validators=[InputRequired(message='Role field cannot be left blank')])

class NewUserForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])
    email = EmailField('email', validators=[Email(), InputRequired(message='Email field cannot be left blank')])
    password = PasswordField('New Password', validators=[InputRequired(message='Password field cannot be left blank'),
                                                         EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password',
                            validators=[InputRequired(message='Confirm Password field cannot be left blank')])
    role = SelectField('role', choices=[('1', 'Student'), ('2', 'Teacher'), ('3', 'HOD')],
                         validators=[InputRequired(message='Role field cannot be left blank')])

class ResourceForm(Form):
    name = StringField('name', validators=[InputRequired(message='Name field cannot be left blank')])
    quantity = StringField('quantity', validators=[InputRequired(message='Quantity field cannot be left blank')])

class RoleForm(Form):
    access_resources = MultiCheckboxField('AccessResources')
    grant_resources = MultiCheckboxField('GrantResources')
    modify_resources = MultiCheckboxField('ModifyResources')

class AccessForm(Form):
    users = SelectField("users")
    resources = SelectField("resources")
    actions = SelectField("actions")


class LoginForm(Form):
    email = EmailField('Email', validators=[Email(message='Invalid Email format'),
                                            InputRequired(message='Email field cannot be left blank'), Length(1, 64)])
    password = PasswordField('Password', validators=[InputRequired('Password field cannot be left blank')])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

