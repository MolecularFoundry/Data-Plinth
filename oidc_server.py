import datetime
import flask
import logging
#from flask import Flask, jsonify
from flask import Flask ,redirect, url_for, request, render_template, jsonify
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlencode
import secrets 
import requests
import json
import globus_sdk





app = Flask(__name__, static_folder='static',template_folder="templates",instance_relative_config=False)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
def Merge(dict1, dict2):
    res = dict1 | dict2
    return res

CLIENT_ID = open(".secrets/Globus-ID").read().strip()
CLIENT_SECRET = open(".secrets/Globus-Secret").read().strip()
print(CLIENT_ID +CLIENT_SECRET)

confidential_client = globus_sdk.ConfidentialAppAuthClient(
    client_id=CLIENT_ID, client_secret=CLIENT_SECRET
)
scopes = "urn:globus:auth:scope:transfer.api.globus.org:all"
cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(confidential_client, scopes)
# create a new client
transfer_client = globus_sdk.TransferClient(authorizer=cc_authorizer)
source_endpoint_id = 
dest_endpoint_id="9d6d994a-6d04-11e5-ba46-22000b92c6ec"
task_data = globus_sdk.TransferData(
    source_endpoint=source_endpoint_id, destination_endpoint=dest_endpoint_id
)
task_data.add_item(
    "test.txt",  # source
    "/~/test.txt",  # dest
)

task_doc = transfer_client.submit_transfer(task_data)
task_id = task_doc["task_id"]
print(f"submitted transfer, task_id={task_id}")
app_key = open(".secrets/app_secret").read().strip()
app.config.update({'OIDC_REDIRECT_URI': "https://mf-scicat.lbl.gov/login-ORCID'",
                   'SECRET_KEY': app_key, 
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})

PROVIDER_NAME = 'orcid'
client_id = open(".secrets/ORCiD_client_id").read().strip()
client_secret = open(".secrets/ORCiD_client_secret").read().strip()

clientmeta = ClientMetadata(
    client_id=client_id,
    client_secret=client_secret)
PROVIDER_CONFIG = ProviderConfiguration(issuer='https://orcid.org/',
                                         client_metadata=clientmeta)

auth = OIDCAuthentication({PROVIDER_NAME: PROVIDER_CONFIG})
def argumentHandler(requestArguments,newArguments):  
    return Merge(requestArguments,newArguments)

@app.route("/")
def home():
    arguments = {}
    arguments["loggedIn"]= bool(auth.valid_access_token())
    if auth.valid_access_token():
        arguments["event"] = True
        arguments["event_type"] = "alert-success"
        arguments["event_text"] = "You have been logged in"
        arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    return render_template("index.html",args = arguments)

@app.route('/login-page')
def loginPage():
    if( bool(auth.valid_access_token())):
        return redirect("/")
    arguments = argumentHandler(requestArguments=request.args,newArguments={})
    return render_template("login.html",args=arguments)

@app.route('/login-ORCID')
@auth.oidc_auth(PROVIDER_NAME)
def loginORCID():
    return redirect("/")

@app.route('/logout')
@auth.oidc_logout
def logout():
    arguments = {}
    arguments["event"] = True
    arguments["event_type"] = "alert-warning"
    arguments["event_text"] = "You have been logged out"
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    encodedURl = "?"+urlencode(arguments)
    return redirect("/"+encodedURl)

@app.route('/profile')
@auth.oidc_auth(PROVIDER_NAME)
#@auth.access_control(PROVIDER_NAME,scopes_required=['read', 'write'])
def profile_route(): 
    arguments={}
    arguments["loggedIn"]= bool(auth.valid_access_token())
    user_session = UserSession(flask.session)
    hidden_key = open(".secrets/MF-Hub-key").read().strip()
    orcid = user_session.userinfo["sub"]
    response = requests.get(url = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser.aspx?key={hidden_key}&orcid={orcid}")
    if(len(response.json())>0):
        arguments["data_set"] = response.json()[0]
    else:
        arguments["event"] = True
        arguments["event_type"] = "alert-danger"
        arguments["event_text"] = "No user data found"
        arguments["data_set"]={}
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    return render_template("profile.html",args=arguments)    

@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
auth.init_app(app)
app.run(host="data-plinth-flask-backend")
