"""
Routes and views for the flask application.
"""

from flask import render_template, flash, redirect, request, session, url_for
from urllib.parse import urlparse


from config import Config
from FlaskWebProject import app, db
from FlaskWebProject.forms import LoginForm, PostForm
from flask_login import current_user, login_user, logout_user, login_required
from FlaskWebProject.models import User, Post

import msal
import uuid

# Blob image base URL
imageSourceUrl = (
    "https://" + app.config["BLOB_ACCOUNT"] + ".blob.core.windows.net/"
    + app.config["BLOB_CONTAINER"] + "/"
)

# -------------------------
# Home / Posts
# -------------------------

@app.route("/")
@app.route("/home")
@login_required
def home():
    posts = Post.query.all()
    return render_template(
        "index.html",
        title="Home Page",
        posts=posts
    )

@app.route("/new_post", methods=["GET", "POST"])
@login_required
def new_post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        post = Post()
        post.save_changes(form, request.files["image_path"], current_user.id, new=True)
        return redirect(url_for("home"))

    return render_template(
        "post.html",
        title="Create Post",
        imageSource=imageSourceUrl,
        form=form
    )

@app.route("/post/<int:id>", methods=["GET", "POST"])
@login_required
def post(id):
    post_obj = Post.query.get(int(id))

    # Delete action
    if request.args.get("action") == "delete":
        if post_obj and post_obj.image_path is not None:
            post_obj.delete_image()
        db.session.delete(post_obj)
        db.session.commit()
        flash(f'post "{post_obj.title}" deleted successfully')
        return redirect(url_for("home"))

    form = PostForm(formdata=request.form, obj=post_obj)
    if form.validate_on_submit():
        post_obj.save_changes(form, request.files["image_path"], current_user.id)
        return redirect(url_for("home"))

    return render_template(
        "post.html",
        title="Edit Post",
        imageSource=imageSourceUrl,
        form=form
    )

# -------------------------
# Login (Manual + Microsoft OAuth)
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()

    # ---------- Manual username/password login ----------
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # Block OAuth-created users from password login
        if user and user.password_hash == "-":
            flash("Not Allowed! Sign in with your Microsoft Account")
            app.logger.warning("Invalid login attempt")
            return redirect(url_for("login"))

        # Invalid username/password
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password")
            app.logger.warning("Invalid login attempt")
            return redirect(url_for("login"))

        # Successful manual login
        login_user(user, remember=form.remember_me.data)
        # (If you login with admin/pass, you will get: "admin logged in successfully")
        app.logger.warning(f"{user.username} logged in successfully")

        flash(f"Welcome {user.username} !")
        next_page = request.args.get("next")

        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for("home")

        return redirect(next_page)

    # ---------- Microsoft OAuth (Sign in with Microsoft button) ----------
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session["state"])
    return render_template("login.html", title="Sign In", form=form, auth_url=auth_url)


@app.route(Config.REDIRECT_PATH)  # e.g. "/auth" (must match Entra redirect URI)
def authorized():
    # 1) State mismatch => unsuccessful access attempt
    if request.args.get("state") != session.get("state"):
        app.logger.warning("Invalid login attempt")
        return redirect(url_for("home"))

    # 2) Microsoft returned an error => unsuccessful access attempt
    if "error" in request.args:
        app.logger.warning("Invalid login attempt")
        return render_template("auth_error.html", result=request.args)

    # 3) Authorization code returned => exchange for token
    if request.args.get("code"):
        cache = _load_cache()

        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            code=request.args["code"],
            scopes=Config.SCOPE,
            redirect_uri=url_for("authorized", _external=True, _scheme="https")
        )

        # Token failure => unsuccessful access attempt
        if not result or "id_token_claims" not in result:
            app.logger.warning("Invalid login attempt")
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")
        preferred = session["user"].get("preferred_username", "")
        username = preferred.split("@")[0] if preferred else None

        if not username:
            app.logger.warning("Invalid login attempt")
            return render_template("auth_error.html", result=result)

        # Ensure user exists in DB (OAuth users have password_hash='-')
        user = User.query.filter_by(username=username).first()
        if not user:
            new_user = User(username=username, password_hash="-")
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(username=username).first()

        login_user(user)
        _save_cache(cache)


        app.logger.warning(f"{user.username} logged in successfully")

        flash(f"Welcome {user.username} !")

    return redirect(url_for("home"))

# -------------------------
# Logout
# -------------------------

@app.route("/logout")
def logout():
    logout_user()

    # If MS login was used, clear session + logout tenant session
    if session.get("user"):
        session.clear()
        return redirect(
            Config.AUTHORITY + "/oauth2/v2.0/logout"
            + "?post_logout_redirect_uri="
            + url_for("login", _external=True, _scheme="https")
        )

    return redirect(url_for("login"))

# -------------------------
# MSAL helpers
# -------------------------

def _load_cache():
    cache = msal.SerializableTokenCache()
    token_cache = session.get("token_cache")
    if token_cache:
        cache.deserialize(token_cache)
    return cache

def _save_cache(cache):
    if cache and cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        client_id=Config.CLIENT_ID,
        authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET,
        token_cache=cache
    )

def _build_auth_url(authority=None, scopes=None, state=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes=scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for("authorized", _external=True, _scheme="https")
    )