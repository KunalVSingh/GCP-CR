from flask import Flask
import os

app = Flask(__name__)

@app.route("/")
def hello():
    return "Successful setup!!! Implicitly operation using Github Repo from GUI "

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
