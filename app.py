from flask import Flask, send_from_directory, request, session, flash, jsonify, make_response
from flask_restful import Api, Resource, reqparse
from flask_cors import CORS #comment this on deployment
from api.HelloApiHandler import HelloApiHandler
# from api.UserApiHandler import UserApiHandler
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_jwt import JWT, jwt_required, current_identity
import jwt
from faunadb import query
from faunadb.client import FaunaClient
from faunadb.objects import Ref
from faunadb.errors import BadRequest, NotFound
from dotenv import load_dotenv
import os, secrets
from functools import wraps
import datetime


# APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
# dotenv_path = os.path.join(APP_ROOT, '.env')
# load_dotenv(dotenv_path)

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

@app.route("/api/v1/scoreboard", methods=["GET", "POST"])
def highscore():
  if request.method == "GET":
    # Get Top 10 high scores in high scores collection
    try:
      # highscores = client.query(
      #   query.get(query.ref(query.collection("highscores")))
      # )
      # highscores = client.query(query.map(
      #   query.paginate(query.documents(query.collection('highscores'))),
      #   query.lambda(x => query.get(x))
      # ))
      # highscores = client.query(
      #   query.map_(
      #     query.lambda_("highscores", query.get(query.var("data"))),
      #     query.paginate(query.match(query.index('top_highscores'))),
      #   )
      # )
      # highscores = client.query(q.get(q.ref(q.collection(collection)
      # Get all highscores from collection
      # highscores = client.query(
      #   query.map_(
      #     query.paginate(query.collection('highscores')),
      #     query.lambda_("data", x => query.get(x))
      #   )
      # )
      # highscores = client.query(
      #   query.get(query.match(query.index("top_highscores"), ))
      # )
      highscores = client.query(
        query.paginate(query.match(query.index("top_highscores")))
      )
      print(highscores)
      print(highscores["data"])

      return jsonify({ "ok": True, "message": "Here are the highscores", "data": highscores["data"]})
    except Exception as e:
      print(e)
      return jsonify({ "ok": False, "message": "Error: Could not GET the highscores"})

  if not session.get('user_id'):
    flash('You are not logged in!', 'warning')
    return {
      "ok": False,
      "message": "You are not logged in."
    }

  

  if request.method == "POST":
    # Validate Data (if time, check against fraud)
    score = request.form["score"]
    username = request.form["username"]

    if not score:
      return jsonify({ "ok": False, "message": "Error: Missing required field: score."})
    if not username:
      return jsonify({ "ok": False, "message": "Error: Missing required field: username."})

    if not int(score) or int(score) < 0 or int(score) > 1000:
      return jsonify({ "ok": False, "message": "Error: You have sent an invalid score. Sus."})

    # if username does not exist in DB, return error
    try:
      user = client.query(
        query.get(query.match(query.index('user_by_username'), username))
      )
    except NotFound:
      return {
        "ok": False,
        "message": "Error: User with this username was not found."
      }

    # Add score to high scores in DB
    result = client.query(
      query.create(
        query.collection("highscores"),
        {"data": {"score": int(score), "username": username}}
      )
    )
    print(result)

    return jsonify({ "ok": True, "message": "Saved your score successfully!" })


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


          if not username or not password:
              return jsonify({ "ok": False, "message": "Error: Missing required fields username and/or password to sign in"})
          # verify if the user details exist

          # auth = request.form # request.authorization

          # if not auth or not auth.username or not auth.password:
          #   return make_response('could not verify', 401, {'Authentication': 'login required', "ok": False})

          flash("received auth")

          try:
              user = client.query(
                      query.get(query.match(query.index('user_by_username'), username))
              )
              # if not user:

          except NotFound:
              flash('Invalid username or password', category='warning')
              return {
                "ok": False,
                "message": "Invalid username or password. Cannot sign you in."
              }
          else:
              if check_password_hash(user['data']['password'], password):
                  print("checked pw hash")
                  user_public_id = user['ref'].id()
                  session['user_id'] = user_public_id
                  exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
                  # exp_date.
                  token = jwt.encode({'public_id': user_public_id, 'exp': exp_date}, app.config['APP_SECRET'], "HS256")
                  flash('Signed in successfully', 'success')
                  return jsonify({
                    "ok": True,
                    "message": "You have signed in successfully!",
                    "data": {
                      "user_id": session['user_id'],
                    },
                    "token": token.decode('UTF-8')
                  })
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
              new_user = client.query(query.create(
                  query.collection('users'),
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

def token_required(f):
  @wraps(f)
  def decorator(*args, **kwargs):
    token = None
    if 'x-access-tokens' in request.headers:
        token = request.headers['x-access-tokens']

    if not token:
      return jsonify({"pk": False, 'message': 'a valid token is missing'})
    
    try:
      data = jwt.decode(token, app.config['APP_SECRET'], algorithms=["HS256"])
      # query for the current user using the public_id of the user
      flash("got data: ", data)
      current_user = client.query(
                query.get(query.match(query.index('user_by_id'), data['public_id']))
        )
      if current_user:
        flash('got the user!')
        return jsonify({ "ok": True, "message": "Got the user! "})
    except:
      return jsonify({"ok": False, 'message': 'token is invalid'})

    return f(current_user, *args, **kwargs)
  return decorator

@app.route("/api/v1/test-protected", methods=["GET", "POST"])
# this decorator serves to enforce having the jwt
@token_required
def get_protected(current_user):
  if not session.get('user_id'):
    flash("You need to be logged in. Missing 'user_id' from session")
    return {
      "ok": False,
      "message": "You need to be logged in. Missing 'user_id' from session"
    }

  # use the JWT for additional auth
  flash("you have authed past the session storage. now testing the JWT...")

  if not current_user.id:
    flash("you don't have the user id")
    return {
      "ok": False,
      "message": "JWT id not found"
    }

  flash("made it through. returning now")

  return {
    "ok": True,
    "message": "Congrats, you have authenticated with JWT",
    "user_id": current_user.id
  }

  

# app.add_url_rule('/api/todos', methods=['GET'], view_func=get_all_todos)
# app.add_url_rule('/api/todos', methods=['POST'], view_func=create_todo)
# app.add_url_rule('/api/todos/<string:id>', methods=['GET'], view_func=get_todo_by_ref_id)
# app.add_url_rule('/api/todos/<string:id>', methods=['PUT'], view_func=update_todo)
# app.add_url_rule('/api/todos/<string:id>', methods=['DELETE'], view_func=delete_todo)

api.add_resource(HelloApiHandler, '/flask/hello')

# if __name__ == '__main__':
#     app.run(debug=True)