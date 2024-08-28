import datetime
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from sqlalchemy import ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
import smtplib


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URL", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    comment_author = relationship("User", back_populates="comments")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

# Parent
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(100), unique=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

# Child
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="posts")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check

def user_only(function):
    @wraps(function)
    @login_required
    def wrapper_function(*args, **kwargs):
        users = db.session.execute(db.select(User)).scalars()
        for user in users:
            if user == current_user or current_user.id == 1:
                return function(*args, **kwargs)

        abort(403)
    return wrapper_function


# def admin_only(function):
#     @wraps(function)
#     @login_required
#     def check(*args, **kwargs):
#         if current_user.id == 1:
#             return function(*args, **kwargs)
#         return abort(403)
#     return check

@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        if user:
            flash("You already signed up with this email. Log in instead. ")
            return redirect(url_for("login"))

        user_name = db.session.execute(db.select(User).where(User.username == request.form.get("username"))).scalar()
        if user_name:
            flash("This username already existed. Enter a new one. ")
            return redirect(url_for("register"))

        hash_password = generate_password_hash(password=request.form.get("password"), method="pbkdf2:sha256",
                                               salt_length=28)

        new_user = User(
            email=request.form.get("email"),
            password=hash_password,
            username=request.form.get("username")
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        if user:
            is_valid = check_password_hash(pwhash=user.password, password=request.form.get("password"))
            if is_valid:
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("The password is incorrect. Please type in again.")
        else:
            flash("The email is incorrect or doesn't exist. Please type in again.")

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text=request.form.get("body"),
                author_id=current_user.id,
                post_id=post_id
            )

            db.session.add(new_comment)
            db.session.commit()

    all_comments = requested_post.comments
    return render_template("post.html", post=requested_post, form=form, comments=all_comments)


@app.route("/new-post", methods=["GET", "POST"])
@user_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        today = datetime.datetime.now()
        new_post = BlogPost(
            title=request.form.get("title"),
            subtitle=request.form.get("subtitle"),
            img_url=request.form.get("img_url"),
            author_id=current_user.id,
            date=today.strftime("%B %d, %Y"),
            body=request.form.get("body"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@user_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@user_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    post_comments = post_to_delete.comments
    for comment in post_comments:
        db.session.delete(comment)
    db.session.delete(post_to_delete)

    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete/comment/<int:post_id>/<int:comment_id>")
@only_commenter
def delete_comment(post_id, comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(os.environ.get("EMAIL"), os.environ.get("PASSWORD"))
            connection.sendmail(
                from_addr=f"{request.form['email']}",
                to_addrs=os.environ.get("EMAIL"),
                msg=f"Subject: Blog User Request\n\n"
                    f"Name: {request.form['name']}\n"
                    f"Email: {request.form['email']}\n"
                    f"Phone: {request.form['phone']}\n"
                    f"Message: {request.form['message']}".encode("utf-8")
            )
        return render_template("contact.html", method="POST")
    else:
        return render_template("contact.html")



if __name__ == "__main__":
    app.run(debug=True, port=5002)
