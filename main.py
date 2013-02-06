import os
import webapp2
import jinja2

import re

from google.appengine.ext import db

import json

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)

import random
import string
import hashlib

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_username(self):
        cookie_str = self.request.cookies.get("user_id")
        user = False
        username = "login"
        if cookie_str:
            try:
                user_id = int(cookie_str.split('_')[0])
                user = User.get_by_id(user_id)
                if user:
                    username = user.username
            except:
                pass
        return username

    def get_nav_entries(self):
        nav_entries = db.GqlQuery("SELECT * FROM Entry "
                                  "ORDER by created DESC "
                                  "LIMIT 10")
        nav_entries = list(nav_entries)
        return nav_entries

class User(db.Model):
    username = db.StringProperty(required = True)
    hashed_password = db.StringProperty(required = True)
    email = db.EmailProperty

class Entry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty()
    user = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class WikiPage(Handler):
    def get(self, path):
        path = self.request.path
        user = self.get_username()
        entries = db.GqlQuery("SELECT * FROM Entry "
                              "WHERE subject = '%s' "
                              "ORDER BY created ASC" % path)
        entries = list(entries)
        
        nav_entries = self.get_nav_entries()
        
        content = ""
        try:
            version = int(self.request.get('v'))
            entry = entries[version]
            content = entry.content
        except:
            try:
                entry = entries[-1]
                content = entry.content
            except:
                content = ""
                if user != "login":
                    self.redirect('/_edit' + path)
                    
        self.render("entry.html", user=user, content=content, path=path, entries=entries, nav_entries=nav_entries)

    def post(self, path):
        search = self.request.get('search')

        self.redirect("/search?q=" + search)

class Front(Handler):
    def get(self):
        user = self.get_username()
        nav_entries = self.get_nav_entries()
        
        self.render("front.html", user=user, nav_entries=nav_entries)

    def post(self):
        search = self.request.get('search')

        self.redirect("/search?q=" + search)

class Search(Handler):
    def get(self):
        user = self.get_username()
        nav_entries = self.get_nav_entries()
        
        search = self.request.get('q')
        entries = db.GqlQuery("SELECT * FROM Entry")
        entries = list(entries)
        found = []
        for entry in entries:
            if search in entry.content:
                found.append(entry)
            if search in entry.subject:
                found.append(entry)
        
        if len(found)>0:
            self.render("search.html", user=user, nav_entries=nav_entries, path=search, found=found)
        else:
            self.render("search.html", user=user, nav_entries=nav_entries, path=search, found=found)

class EditPage(Handler):
    def get(self, path):
        path = self.request.path
        user = self.get_username()
        path = path[6:]
        if user == "login":
            self.redirect('%s' % path)
        entries = db.GqlQuery("SELECT * FROM Entry "
                              "WHERE subject = '%s' "
                              "ORDER BY created DESC" % path)
        entries = list(entries)
        
        nav_entries = self.get_nav_entries()
        
        try:
            entry = entries[0]
            content = entry.content
        except:
            entry = None
            content = ""
            
        self.render("newpost.html", user=user, entry=entry, content=content, path=path, nav_entries=nav_entries)
        
    def post(self, path):
        content = self.request.get("content")

        e = Entry(subject=path, content=content)
        e.put()
        self.response.out.write(path)
        self.redirect('%s' % path)
        
class HistoryPage(Handler):
    def get(self, path):
        path = self.request.path
        path = path[9:]
        user = self.get_username()
        entries = db.GqlQuery("SELECT * FROM Entry "
                              "WHERE subject = '%s' "
                              "ORDER BY created ASC" % path)
        entries = list(entries)
        if len(entries) > 0:
            entryexists = True
            
        nav_entries = self.get_nav_entries()
        
        self.render("history.html", user=user, entryexists=entryexists, path=path, entries=entries, nav_entries=nav_entries)

class LoginSignupHandler(Handler):
    def make_salt(self):
        salt = ''
        for x in range(5):
            salt += random.choice(string.letters)
        return salt

    def make_pw_hash(self, name, pw, salt=None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s_%s' % (h, salt) 

class Signup(LoginSignupHandler):
    def get(self):
        nav_entries = self.get_nav_entries()
        
        self.render('signup.html', user="login", nav_entries=nav_entries)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        val_username = self.check_user(username)
        val_username_str = self.valid_username(username)
        val_password = self.valid_password(password)
        val_verify = self.valid_verify(verify, password)
        val_email = self.valid_email(email)

        nav_entries = self.get_nav_entries()
        
        params = dict(username = username, email = email, nav_entries=nav_entries, user="login")

        if val_username:
            params['error_username'] = "User already exists"

        if not val_username_str:
            params['error_username'] = "Not a valid username"

        if not val_password:
            params['error_password'] = "Not a valid password"

        if not val_verify:
            params['error_verify'] = "Passwords don't match"

        if not val_email:
            params['error_email'] = "Not a valid email"

        if val_username_str and val_password and val_verify and val_email and not val_username:
            user_hash = self.make_pw_hash(username, password)
            u = User(username = username, hashed_password = user_hash, email = email)
            u.put()
            user_id = u.key().id()
            cookie_hash = "%s_%s" % (user_id, user_hash)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % cookie_hash)
            self.redirect("/")
        else:
            self.render("signup.html", **params)
            
    def check_user(self, username):
        q = User.all()
        q.filter("username =", username)
        user = q.get()
        if user:
            return True
            
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    def valid_username(self, username):
        return self.USER_RE.match(username)

    PASS_RE = re.compile(r"^.{3,20}$")
    def valid_password(self, password):
        return self.PASS_RE.match(password)

    def valid_verify(self, password, verify):
        if password == verify:
            return True

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    def valid_email(self, email):
        if email == "":
            return True
        return self.EMAIL_RE.match(email)
    
class Login(LoginSignupHandler):
    def get(self):
        self.render_login(username="", error_pass="", error_user="")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        nav_entries = self.get_nav_entries()

        q = User.all()
        q.filter("username =", username)
        user = q.get()

        if user and password:
            user_id = user.key().id()
            stored_hash = str(user.hashed_password)
            salt = stored_hash.split('_')[1]
            new_hash = self.make_pw_hash(username, password, salt)
            if new_hash == stored_hash:
                cookie_hash = "%s_%s" % (user_id, stored_hash)
                self.response.headers.add_header('Set-Cookie', 'user_id=%s' % cookie_hash)
                self.redirect("/")
            else:
                error_pass = "Incorrect password"
                error_user = ""
                self.render_login(username, error_pass, error_user)
        elif not user:
            error_user = "Incorrect username"
            error_pass = ""
            self.render_login(username, error_pass, error_user)
        elif not password:
            error_pass = "Enter a password"
            error_user = ""
            self.render_login(username, error_pass, error_user)

    def render_login(self, username, error_pass, error_user):
        nav_entries = self.get_nav_entries()
        self.render("login.html", username=username, error_pass=error_pass, error_user=error_user,
                    nav_entries=nav_entries, user="login")

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/")

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([
                               ('/signup/?', Signup),
                               ('/login/?', Login),
                               ('/logout/?', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/', Front),
                               ('/search/?', Search),
                               (PAGE_RE, WikiPage)
                               ],
                              debug=True)
