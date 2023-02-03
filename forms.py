from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, EqualTo
from flask_ckeditor import CKEditorField
import random

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign me Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")

class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class ForgotPassword(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField("Send Code")

class CreateNewPassword(FlaskForm):
    email_code = StringField('Verify Code', validators=[DataRequired()])
    new_password = PasswordField("Create New Password", validators=[DataRequired()])
    repeat_new_password = PasswordField('Repeat New Password', validators=[DataRequired(), EqualTo('new_password',message='Passwords must match')])
    submit = SubmitField("Login")


class GenerateDummy:
    def generate_dummy_password(self):
        letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                   'u',
                   'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                   'Q',
                   'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'v', 'R']
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

        nr_letters = 3
        nr_symbols = 2
        nr_numbers = 3

        password_list = [random.choice(letters) for _ in range(nr_letters)]

        password_list += [random.choice(symbols) for _ in range(nr_symbols)]

        password_list += [random.choice(numbers) for _ in range(nr_numbers)]

        random.shuffle(password_list)

        password = ''.join(password_list)
        return password

