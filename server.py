###########################################
# FileName:server.py
# Author:Jeffrey Fulmer Gardner
# Package: Ingest Sender.
# Description. Server.py holds the routes for rendering a simple page for file submission
###########################################
import requests
from flask import Flask ,redirect, url_for, request, render_template
##################Global Vars######################

app = Flask(__name__, static_folder='static',template_folder="templates",instance_relative_config=False)
@app.route("/")
def indexRoute():




    return render_template("index.html",)
@app.route("/login",methods = ["GET"])
def loginPageRoute():
    return render_template("login.html",)
@app.route("/auth/orcid/callback",methods = ["POST"])
def loginActionRoute():
    URL="http://sandbox.orcid.org/oauth/token"
    HEADERS={"Accept": "application/json","Content-Type": "application/x-www-form-urlencoded"}
    DATA = {"client_id":"[Your client ID]","client_secret":"[Your client secret]","grant_type":"authorization_code","code":"Six-digit code","redirect_uri":"/"}
    response = requests.post(url=URL,headers = HEADERS,data=DATA)
    redirect("/")
app.run(debug=True)