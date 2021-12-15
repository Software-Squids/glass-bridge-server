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
# import flask_praetorian

# APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
# dotenv_path = os.path.join(APP_ROOT, '.env')
# load_dotenv(dotenv_path)

app = Flask(__name__, static_url_path='', static_folder='frontend/build')

# guard = flask_praetorian.Praetorian()

app.secret_key = os.environ.get('APP_SECRET')
app.config['APP_SECRET']=os.environ.get('APP_SECRET')
app.config['JWT_ACCESS_LIFESPAN'] = {"hours": 24}
app.config['JWT_REFRESH_LIFESPAN'] = {"days": 30}

client = FaunaClient(secret=os.environ.get('FAUNA_DB_KEY'), domain="db.us.fauna.com")

# Init Praetorian
# guard.init_app(app)

CORS(app) #comment this on deployment
api = Api(app)

@app.route("/", defaults={'path':''})
def serve(path):
    return send_from_directory(app.static_folder,'index.html')

# app.add_resource(UserApiHandler, '/api/v1/user')

@app.route("/api/v1/scoreboard", methods=["GET", "POST"])
def highscore():
  if request.method == "GET":

    # Establish the query to filter scores by (easy, medium, hard)
    difficulty = request.args.get("difficulty", type=str)
    if not difficulty or difficulty == None:
      print("no difficulty submitted.")
      return make_response(jsonify({"ok": False, "message": "Error: Please query for a specific difficulty"}), 400)

    if difficulty != "easy" and difficulty != "medium" and difficulty != "hard":
      print("invalid difficulty submitted:", difficulty)
      return make_response(jsonify({ "ok": False, "message": "Error: Invalid difficulty submitted. Supported options are: easy, medium, or hard" }), 400)

    # Get Top 10 high scores in high scores collection
    # - could use paginate's size option to set to 10, if can filter or sort
    try:
      highscores = client.query(
        query.paginate(query.match(query.index("highscores_by_difficulty"), difficulty))
      )
      print("got highscores:", highscores)

      # Sort and filter the highscores here...

      return jsonify({ "ok": True, "message": "Here are the highscores", "data": highscores})
    except Exception as e:
      print(e)
      return make_response(jsonify({ "ok": False, "message": "Error: Could not GET the highscores"}), 500)

  if not jwt_verify(request.headers):
    flash("User jwt not found. returning", "warning")
    return make_response(jsonify({ "ok": False, "message": "Error: Invalid or missing authentication token" }), 400)

  if request.method == "POST":
    # Validate Data (if time, check against fraud)
    score = request.form["score"]
    username = request.form["username"]
    difficulty = request.form["difficulty"]

    if not score:
      return make_response(jsonify({ "ok": False, "message": "Error: Missing required field: score."}), 400)
    if not username:
      return make_response(jsonify({ "ok": False, "message": "Error: Missing required field: username."}), 400)
    if not difficulty:
      return make_response(jsonify({ "ok": False, "message": "Error: Missing required field: difficulty."}), 400)

    if not int(score) or int(score) < 0 or int(score) > 1000:
      return make_response(jsonify({ "ok": False, "message": "Error: You have sent an invalid score. Sus."}), 400)

    if difficulty != "easy" and difficulty != "medium" and difficulty != "hard":
      return make_response(jsonify({ "ok": False, "message": "Error: Only supported difficulties are: easy, medium, or hard" }), 400)

    # if username does not exist in DB, return error
    try:
      user = client.query(
        query.get(query.match(query.index('user_by_username'), username))
      )
    except NotFound:
      return make_response(
        jsonify({
          "ok": False,
          "message": "Error: User with this username was not found."
        }),
        400
      )

    # TODO: First check if the score is in the top 10 for the given difficulty

    # Add score to high scores in DB
    result = client.query(
      query.create(
        query.collection("highscores"),
        {"data": {"score": int(score), "username": username, "difficulty": difficulty}}
      )
    )
    print(result)

    return make_response(jsonify({ "ok": True, "message": "Saved your score successfully!" }), 201)


@app.route("/api/v1/user/signin", methods=["GET", "POST"])
def signin():
      if request.method =='POST':
          # get the user details
          username = request.form['username']
          password = request.form['password']


          if not username or not password:
              return make_response(jsonify({ "ok": False, "message": "Error: Missing required fields username and/or password to sign in"}), 400)
          # verify if the user details exist

          flash("received auth", "info")

          try:
              user = client.query(
                query.get(query.match(query.index('user_by_username'), username))
              )
              # if not user:

          except NotFound:
              flash('Invalid username or password', category='warning')
              return make_response(
                jsonify({
                  "ok": False,
                  "message": "Invalid username or password. Cannot sign you in."
                }),
                400
              )
          else:
              if check_password_hash(user['data']['password'], password):
                  print("checked pw hash")
                  user_public_id = user['ref'].id()
                  session['user_id'] = user_public_id
                  # Will expire in 45 minutes
                  exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
                  print("will hash now")
                  # exp_date.
                  token = jwt.encode({'public_id': user_public_id, 'exp': exp_date}, app.config['APP_SECRET'], "HS256")
                  flash('Signed in successfully', 'success')
                  print("will return jsonify now")
                  return jsonify({
                    "ok": True,
                    "message": "You have signed in successfully!",
                    "data": {
                      "user_id": str(user_public_id, encoding="utf-8"),
                    },
                    "access_token": str(token, encoding="utf-8")
                  })
                  # res.set_cookie("access_token", token)
              else:
                  flash('Invalid usernasme or password', 'warning')
                  return make_response(jsonify({
                    "ok": False,
                    "message": "Invalid username or password entered. Cannot sign you in."
                  }), 400)
      if request.method == 'GET':
          flash("User wants to GET signin")
          return make_response(jsonify({
            "ok": False,
            "message": "GET /signin is not implemented yet. What should it do?"
          }), 400)

@app.route("/api/v1/user/signup", methods=["GET", "POST"])
def signup():
      # if session.get('user_id'):
      #   flash('You are logged in!', 'warning')
      #   return {
      #     "ok": True,
      #     "message": "You are logged in already."
      #   }
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
            return make_response(jsonify({
              "ok": False,
              "message": "Username is not valid. It must be between 1-20 characters in length"
            }), 400)

          if password != request.form['confirm_password']:
              flash('password fields not equal', 'warning')
              return make_response(jsonify({
                "ok": False,
                "message": "Password fields do not match"
              }), 400)
          
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
              return make_response(
                jsonify({
                  "ok": False,
                  "message": "This username already exists. Please sign in or pick another one."
                }),
                401
              )
          else:
              user_public_id = new_user['ref'].id()
              session['user_id'] = user_public_id
              flash('Account created successfully', 'success')

              # JWT again
              exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
              token = jwt.encode({'public_id': user_public_id, 'exp': exp_date}, app.config['APP_SECRET'], "HS256")
              return jsonify({
                "ok": True,
                "message": "Account created successfully!",
                "access_token": str(token, encoding="utf-8")
              })
              # res.set_cookie("access_token", token)

      elif request.method == 'GET':
        return make_response(jsonify({
          "ok": False,
          "message": "Please only POST to /user/signup"
        }), 400)

@app.route("/api/v1/user/signout", methods=["GET", "POST"])
def signout():
    # if not session.get('user_id'):
    #     flash('You need to be logged in to do this!', 'warning')
    #     return {
    #       "ok": False,
    #       "message": "You are not logged in yet, so you cannot sign out"
    #     }
    if session.get('user_id'):
      session.pop('user_id', None)

    res = make_response(jsonify({ "ok": True, "message": "You have logged out successfully!"}), 200)
    res.delete_cookie("access_token")
    flash('Signed out successfully', 'success')
    return res

# Will not work
# @app.route('/api/v1/refresh', methods=['POST'])
# def refresh():
#     """
#     Refreshes an existing JWT by creating a new one that is a copy of the old
#     except that it has a refrehsed access expiration.
#     .. example::
#        $ curl http://localhost:5000/api/refresh -X GET \
#          -H "Authorization: Bearer <your_token>"
#     """
#     print("refresh request")
#     old_token = request.get_data()
#     # new_token = guard.refresh_jwt_token(old_token)
#     ret = {'access_token': new_token}
#     return ret, 200


def jwt_verify(headers):
  try:
    token = headers.get("access_token")
    print("got token (from headers):", token)
    decoded = jwt.decode(token, app.config['APP_SECRET'], algorithms=["HS256"])
    # DO WHATEVER YOU WANT WITH THE DECODED TOKEN
    print('dec jwt:', decoded)
    return True
  except Exception as e:
    print("error in jwt_verify: ", e)
    return False

# def jwt_verify_old(cookies):
#   try:
#     print("cookies:", cookies)
#     token = cookies.get("access_token")
#     print("got token (from cookies):", token)
#     decoded = jwt.decode(token, app.config['APP_SECRET'], algorithms=["HS256"])
#     # DO WHATEVER YOU WANT WITH THE DECODED TOKEN
#     print('dec jwt:', decoded)
#     return True
#   except Exception as e:
#     print("error in jwt_verify: ", e)
#     return False

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
      "message": "Access token id not found"
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