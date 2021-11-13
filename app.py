from flask import Flask, send_from_directory, request, session, flash
from flask_restful import Api, Resource, reqparse
from flask_cors import CORS #comment this on deployment
from api.HelloApiHandler import HelloApiHandler
# from api.UserApiHandler import UserApiHandler
from werkzeug.security import generate_password_hash, check_password_hash
from faunadb import query as q
from faunadb.client import FaunaClient
from faunadb.objects import Ref
from faunadb.errors import BadRequest, NotFound
from dotenv import load_dotenv
import os, secrets


APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)

app = Flask(__name__, static_url_path='', static_folder='frontend/build')

app.secret_key = os.environ.get('APP_SECRET')
app.config['APP_SECRET']=os.environ.get('APP_SECRET')
client = FaunaClient(secret=os.environ.get('FAUNA_DB_KEY'), domain="db.us.fauna.com")

CORS(app) #comment this on deployment
api = Api(app)

@app.route("/", defaults={'path':''})
def serve(path):
    return send_from_directory(app.static_folder,'index.html')

# app.add_resource(UserApiHandler, '/api/v1/user')

@app.route("/api/v1/user/signin", methods=["GET", "POST"])
def signin():
      if session.get('user_id'):
              flash('You are logged in!', 'warning')
              return {
                "ok": True,
                "message": "You are logged in already."
              }
      if request.method =='POST':
          # get the user details
          username = request.form['username']
          password = request.form['password']
          # verify if the user details exist
          try:
              user = client.query(
                      q.get(q.match(q.index('user_by_username'), username))
              )
          except NotFound:
              flash('Invalid username or password', category='warning')
              return {
                "ok": False,
                "message": "Invalid username or password. Cannot sign you in."
              }
          else:
              if check_password_hash(user['data']['password'], password):
                  session['user_id'] = user['ref'].id()
                  flash('Signed in successfully', 'success')
                  return {
                    "ok": True,
                    "message": "You have signed in successfully!",
                    "data": {
                      "user_id": session['user_id']
                    }
                  }
              else:
                  flash('Invalid usernasme or password', 'warning')
                  return {
                    "ok": False,
                    "message": "Invalid username or password entered. Cannot sign you in."
                  }
      if request.method == 'GET':
          flash("User wants to GET signin")
          return {
            "ok": False,
            "message": "GET /signin is not implemented yet. What should it do?"
          }

@app.route("/api/v1/user/signup", methods=["GET", "POST"])
def signup():
      if session.get('user_id'):
              flash('You are logged in!', 'warning')
              return {
                "ok": True,
                "message": "You are logged in already."
              }
      if request.method =='POST':
          username = request.form['username']
          # email = request.form['email']
          password = request.form['password']
          # email_regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
          # if not re.search(email_regex, email) or not 6 < len(password) < 20:
          #     flash('Invalid email or password!, password needs to be between 6 and 20 characters', 'warning')
              # return render_template('signup.html')
          if not username or len(username) < 1 or len(username) > 20:
            flash("username is malformatted", "warning")
            return {
              "ok": False,
              "message": "Username is not valid. It must be between 1-20 characters in length"
            }

          if password != request.form['confirm_password']:
              flash('password fields not equal', 'warning')
              return {
                "ok": False,
                "message": "Password fields do not match"
              }
          
          password_hash = generate_password_hash(password)
          user = {'username': username, 'password': password_hash}
          try:
              # store user data to db
              new_user = client.query(q.create(
                  q.collection('users'),
                  {'data': user}
              ))
          except BadRequest:
              flash('Username already exists')
              return {
                "ok": False,
                "message": "This username already exists. Please sign in or pick another one."
              }
          else:
              session['user_id'] = new_user['ref'].id()
              flash('Account created successfully', 'success')
              return {
                "ok": True,
                "message": "Account created successfully!"
              }
      elif request.method == 'GET':
        return {
          "ok": False,
          "message": "Please only POST to /user/signup"
        }

@app.route("/api/v1/user/signout", methods=["GET", "POST"])
def signout():
    if not session.get('user_id'):
        flash('You need to be logged in to do this!', 'warning')
        return {
          "ok": False,
          "message": "You are not logged in yet, so you cannot sign out"
        }
    else:
        session.pop('user_id', None)
        flash('Signed out successfully', 'success')
        return {
          "ok": True,
          "message": "You have logged out successfully!"
        }

# app.add_url_rule('/api/todos', methods=['GET'], view_func=get_all_todos)
# app.add_url_rule('/api/todos', methods=['POST'], view_func=create_todo)
# app.add_url_rule('/api/todos/<string:id>', methods=['GET'], view_func=get_todo_by_ref_id)
# app.add_url_rule('/api/todos/<string:id>', methods=['PUT'], view_func=update_todo)
# app.add_url_rule('/api/todos/<string:id>', methods=['DELETE'], view_func=delete_todo)

api.add_resource(HelloApiHandler, '/flask/hello')

# if __name__ == '__main__':
#     app.run(debug=True)