from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_wtf import FlaskForm


class LoginForm(FlaskForm):  # extending flask-from class
    username = StringField('username', validators=[InputRequired(), Length(min=4,
                                                                           max=15)])  # using string field from wtform class and others
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class UploadNewsForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=10, max=200)])
    desc = StringField('Description', validators=[InputRequired(), Length(min=24, max=2000)])
    category = SelectField('Category', choices=[('predict', 'Predict'), ('politics', 'Politics'), ('sport', 'Sports'),
                                                ('business', 'Business'), ('entertainment', 'Entertainment'),
                                                ('tech', 'Technology')])
    submit = SubmitField('Submit')


