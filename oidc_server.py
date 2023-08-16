import datetime
import flask
import logging
import re
#from flask import Flask, jsonify
from flask import Flask ,redirect, url_for, request, render_template, jsonify
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.datastructures import MultiDict
from urllib.parse import urlencode
import secrets 
import requests
import json
import pyscicat
import os
import uuid
from pathlib import Path
from dotenv import load_dotenv
import requests
from urllib.parse import urljoin
load_dotenv()
from pyscicat.client import encode_thumbnail, ScicatClient 
from pyscicat.model import (
     Attachment,
     Datablock,
     DataFile,
     Dataset,
     Ownable,RawDataset
)




# See https://flask.palletsprojects.com/en/2.0.x/config/
app = Flask(__name__, static_folder='static',template_folder="templates",instance_relative_config=False)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
def Merge(dict1, dict2):
    res = dict1 | dict2
    return res
#app_key = secrets.token_hex()
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app_key = app_key = open(".secrets/app_secret").read().strip()
app.config.update({'OIDC_REDIRECT_URI': "https://data-plinth.lbl.gov/login-ORCID'",
                   'SECRET_KEY': app_key,  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': False})

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


class user():
    first_name=""
    last_name=""
    email=""
    lbl_email=""
    orcid=""

@app.route("/data-input")
def data_input():
    if( not bool(auth.valid_access_token())):
        return redirect("/")
    user_session = UserSession(flask.session)
    hidden_key = open(".secrets/MF-Hub-key").read().strip()
    orcid = user_session.userinfo["sub"]
    #orcid = "0000-0003-4736-0743"
    pidUrl = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser-simple.aspx?key={hidden_key}&orcid={orcid}"
    userinfoUrl = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser.aspx?key={hidden_key}&orcid={orcid}"
    userInfoResponse = requests.get(url=userinfoUrl)
    userInfo = userInfoResponse.json()[0]
    dataPlinthUser = user()
    dataPlinthUser.first_name = userInfo["first_name"]
    dataPlinthUser.last_name = userInfo["last_name"]
    dataPlinthUser.email = userInfo["email"]
    dataPlinthUser.lbl_email = userInfo["lbl_email"]
    dataPlinthUser.orcid = orcid
    ## get authrorized pids
    pidResponse = requests.get(url = pidUrl)
    pids = pidResponse.content.decode("utf-8").strip("[").strip("]").split(",")
    arguments = {}
    arguments["loggedIn"]= bool(auth.valid_access_token()) 
    arguments["ListOfPids"] = pids
    arguments["user"] = dataPlinthUser
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    return render_template("data-input.html",args = arguments)

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
    base_url="https://mf-scicat.lbl.gov/api/v3/"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        }
    response = requests.post(
                urljoin(base_url, "Users/login"),
                json={"username": os.getenv("usr"), "password":os.getenv("pw")},
                stream=False,
                verify=True,
            )
    token = response.json()["id"]
    headers["Authorization"] = f"Bearer {token}"
    params = {
    "filter":{"""{"where":{"owner":\""""+orcid+""""}}"""}}
    response = requests.get(url=urljoin(base_url,"datasets/"),params=params,headers=headers,stream=False,verify=True)

    if(len(response.json())>0):
        arguments["data_set"] = response.json()
    else:
        arguments["event"] = True
        arguments["event_type"] = "alert-danger"
        arguments["event_text"] = "No user data found"
        arguments["data_set"]={}
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    return render_template("profile.html",args=arguments)    


@app.route("/createDataset",methods=['POST'])
def createDataset():
    
    
    ## create Scicat client
    scicat = ScicatClient(base_url="https://mf-scicat.lbl.gov/api/v3",username=os.getenv("usr"),password=os.getenv("pw"))
    ## create MF Admin client infromation 
    user_session = UserSession(flask.session)
    hidden_key = open(".secrets/MF-Hub-key").read().strip()
    orcid = user_session.userinfo["sub"]


    ###GET PIDs
    pidUrlString = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser-simple.aspx?key={hidden_key}&orcid={orcid}"
    ## get authrorized pids
    pidResponse = requests.get(url = pidUrlString)
    pidsList = list(pidResponse.json())
    ## get form data
    formData = request.form
    pidFromForm =str(formData["ProposalID"]).strip('"')
    ###GET USER DATA

    return 
    if pidFromForm in pidsList:
        if 'file' not in request.files:
            return redirect("/data-input")
        file = request.files['file']
        if file.filename == '':
            return redirect("/data-input")
        if file and allowed_file(file.filename):
            directoryPath =os.path.join(app.config['UPLOAD_FOLDER'], f"{pidFromForm}/")
            filename = f"{directoryPath}{str(uuid.uuid4())}-{secure_filename(file.filename)}"
        if not os.path.exists(directoryPath):
            os.makedirs(directoryPath)
        file.save(filename)
        ownable = Ownable(ownerGroup=str(pidFromForm), accessGroups=[str(pidFromForm)])
        dataset = RawDataset(
            ownerGroup="Admin",    #Needed
            description=formData["desciptionValue"], #Optional
            owner=orcid, #needed
            orcidOfOwner=orcid, #optional
            principalInvestigator = "Jeff",#Needed
            contactEmail="JeffreyFulmerGardner@outlook.com", #Needed
            creationLocation="Moleculor Foundry", 
            type="raw", #Needed
            sourceFolder=directoryPath,##Needed 
            accessGroups=[pidFromForm],
            creationTime=datetime.datetime.now().isoformat(),#Needed
            )
        data_file = DataFile(path=filename, size=os.path.size(filename))
        data_block = Datablock(size=42,
                       version=1,
                       datasetId=dataset_id,
                       dataFileList=[data_file])
        scicat.upload_datablock(data_block) 
        dataset_id = scicat.datasets_create(dataset)
        attachment = Attachment(
            ownerGroup=pidFromForm,
            datasetId=dataset_id,
            thumbnail=encode_thumbnail(filename),
            caption="scattering image",
            )

        scicat.upload_attachment(attachment)

    return redirect("/profile")
@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
auth.init_app(app)

UPLOAD_FOLDER = './static/images/datasetImages/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.run(host="data-plinth-flask-backend",debug=True)
