from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPassword, CreateNewPassword, GenerateDummy
from flask_gravatar import Gravatar
import smtplib

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


from functools import wraps


# create admin only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)

        return f(*args, **kwargs)

    return decorated_function


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __table__name = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')
    dummy_password = db.Column(db.String(100), nullable=True)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship('User', back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text())
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship('User', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You're already signed up with that email, Please Login instead")
            return redirect(url_for('login'))

        hash_and_salt_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            password=hash_and_salt_password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Incorrect password, Please try again')
                return redirect(url_for('login'))
        else:
            flash("That email does not exists, please try again")
            return redirect(url_for('login'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    # comments = Comment.query.all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment_text.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('You need to login or register to comment.')
            return redirect(url_for('login'))
    return render_template("post.html", form=form, post=requested_post, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        data = request.form
        with smtplib.SMTP('smtp.gmail.com') as connection:
            connection.starttls()
            connection.login(user='bittu.ponna@gmail.com', password='rfdjirkedsuhbezy')
            connection.sendmail(from_addr='bittu.ponna@gmail.com',
                                to_addrs='bittu.ponna@gmail.com',
                                msg=f"Subject:MESSAGE\n\nName:{data['name']}\nEmail:{data['email']}\n"
                                    f"Phone NO:{data['tele']}\nMessage:{data['message']}")
        return render_template('contact.html', msg_sent=True)
    return render_template("contact.html", msg_sent=False)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/forgot_password", methods=["POST", "GET"])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            email = form.email.data
            dummy = GenerateDummy()
            dummy_password = dummy.generate_dummy_password()
            user.dummy_password = dummy_password
            with smtplib.SMTP(host='smtp.gmail.com') as connection:
                connection.starttls()
                connection.login(user='bittu.ponna@gmail.com', password='rfdjirkedsuhbezy')
                connection.sendmail(from_addr='bittu.ponna@gmail.com',
                                    to_addrs=email,
                                    msg=f"Subject:Code\n\nHi:{ user.name }\n Please reset your Password by using the code: {dummy_password}")
            db.session.commit()
            return redirect(url_for('create_new_pass', email=email))

        else:
            flash("Email Doesn't exists, Please try again or Register Instead")
            return redirect(url_for('forgot_password'))
    return render_template('forgot-password.html', form=form)


@app.route('/create-new-password', methods=["POST", "GET"])
def create_new_pass():
    form = CreateNewPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=request.args.get('email')).first()
        if user.dummy_password == form.email_code.data:
            hash_and_salt_password = generate_password_hash(
                form.new_password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            user.password = hash_and_salt_password
            user.dummy_password = ''
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Invalid Code, Please try Again!')
    return render_template('create-new-password.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)
