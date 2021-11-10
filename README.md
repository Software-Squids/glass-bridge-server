# Glass Bridge Server

This is a Flask backend to serve the react app for the Glass Bridge Memory Game.

### Getting Started

1. Clone the repository: `git clone <url>`

2. Create / activate the virtual environment: `source venv/bin/activate`, or `python -m venv venv` to create for the first time

3. Install all requirements if not done already: `pip install -r requirements.txt`

4. Run the flask app: `flask run` - This should start running the app locally on `localhost:5000`


### Future Goals

After deploying the React app to Heroku, I would like to add some more features of a REST api.
Features such as:

- Scoreboard / Highscores list
- Minimal user information, such as optional `username` field, no passwords
...
