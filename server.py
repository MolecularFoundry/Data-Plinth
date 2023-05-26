###########################################
# FileName:server.py
# Author:Jeffrey Fulmer Gardner
# Package: Ingest Sender.
# Description. Server.py holds the routes for rendering a simple page for file submission
###########################################
import requests
from flask import Flask ,redirect, url_for, request, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from oauthlib.oauth2 import WebApplicationClient
from uuid import uuid4
##################Global Vars######################

app = Flask(__name__, static_folder='static',template_folder="templates",instance_relative_config=False)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

@app.route("/")
def indexRoute():
    if(len(request.args)>0):
        if "name" in request.args.keys():
            return render_template("index.html",name =f"Welcome {request.args['name']}")
    return render_template("index.html",name="Please login")
@app.route("/login",methods = ["GET"])
def loginPageRoute():
    return render_template("login.html",)
@app.route("/auth/orcid/callback",methods = ["GET"])
def loginActionRoute():
    name = "Error"
    if(len(request.args)>0):
        if "code" in request.args.keys():
            code = request.args["code"]
        client_id = open(".secrets/ORCiD_client_id").read().strip()
        client_secret = open(".secrets/ORCiD_client_secret").read().strip()
        redirectaddress="https://mf-scicat.lbl.gov/auth/orcid/callback"
        headers = {"Accept": "application/json","Content-Type": "application/x-www-form-urlencoded"}
        data  = f"client_id={client_id}&client_secret={client_secret}&grant_type=authorization_code&code={code}&redirect_uri=https://mf-scicat.lbl.gov/auth/orcid/callback"
        response = requests.post('https://orcid.org/oauth/token', headers=headers, data=data)
        token = response.json()["access_token"]
        header = {'Authorization': 'Bearer {}'.format(token)}
        info_response = requests.get("https://orcid.org/oauth/userinfo", headers=header)
        name =str(response.json()["name"]) + "                orcid:"+ str(response.json()["orcid"])
    else:
        name ="Error"
    return redirect(f"/?name={name}")


app.run(debug=True,host="data-plinth-flask-backend")