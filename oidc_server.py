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
import globus_sdk
from uuid_extensions import uuid7, uuid7str
import base58
import pyscicat
import os
import uuid
from pathlib import Path
from dotenv import load_dotenv
import requests
from urllib.parse import urljoin
load_dotenv()
from MF_Hdf5 import MF_Hdf5_Decoder
from pyscicat.pyscicat.client import encode_thumbnail, ScicatClient 
from pyscicat.pyscicat.model import (
     Attachment,
     Datablock,
     DataFile,
     Dataset,
     Ownable,
     RawDataset,
     OrigDatablock
)
import h5py




# See https://flask.palletsprojects.com/en/2.0.x/config/
app = Flask(__name__, static_folder='static',template_folder="templates",instance_relative_config=False)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
def Merge(dict1, dict2):
    res = dict1 | dict2
    return res
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
GlOBUS_CLIENT_ID = open(".secrets/Globus-ID").read().strip()
GlOBUS_CLIENT_SECRET = open(".secrets/Globus-Secret").read().strip()

UPLOAD_FOLDER = './static/images/datasetImages/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

confidential_client = globus_sdk.ConfidentialAppAuthClient(client_id=GlOBUS_CLIENT_ID, client_secret=GlOBUS_CLIENT_SECRET)
def globusTransfer(fullFileName):
    fullFileName=UPLOAD_FOLDER+"html-assets/static/images/datasetImages/h5sample.h5"
    scopes = "urn:globus:auth:scope:transfer.api.globus.org:all"
    cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(confidential_client, scopes)
    # create a new client
    transfer_client = globus_sdk.TransferClient(authorizer=cc_authorizer)
    
    local_ep = globus_sdk.LocalGlobusConnectPersonal()
    ep_id = local_ep.endpoint_id
    source_endpoint_id = "fdc8eac4-3d48-11ee-b694-812118bf21b5"# ep_id# "4fd03404-512f-4a41-a1a6-8df5f2aef9e3"
    dest_endpoint_id="9d6d994a-6d04-11e5-ba46-22000b92c6ec"
    task_data = globus_sdk.TransferData(transfer_client=transfer_client,source_endpoint=source_endpoint_id, destination_endpoint=dest_endpoint_id)
    task_data.add_item(
        fullFileName,  # source
        "/~/h5sample.h5",  # dest
    )
    task_doc = transfer_client.submit_transfer(task_data)
    task_id = task_doc["task_id"]
    print(f"submitted transfer, task_id={task_id}")
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
    def fullname(self):
        return f"{self.first_name} {self.last_name}"

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
@auth.oidc_auth(PROVIDER_NAME)
@app.route("/profile/dataset/<requested_dataset_id>",methods=["GET"])
def get_dataset(requested_dataset_id):
    arguments={}
    arguments["loggedIn"]= bool(auth.valid_access_token())
    user_session = UserSession(flask.session)
    hidden_key = open(".secrets/MF-Hub-key").read().strip()
    orcid = user_session.userinfo["sub"]


    ##Get list of allowed Datasets
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
    dataset_response = requests.get(url=urljoin(base_url,"datasets/"),params=params,headers=headers,stream=False,verify=True)
    


    if(len(response.json())>0):
        allowed_data_sets = []
        for dataset in dataset_response.json():
            allowed_data_sets.append(dataset["_id"])
        if requested_dataset_id in allowed_data_sets:
            arguments["event"] = True
            arguments["event_type"] = "alert-sucess"
            arguments["event_text"] = "Data set loaded"
            data_block_params = {"fields":{"{\"datasetId\":\""+requested_dataset_id+"\"}"}}
            arguments["data_blocks"] = requests.get(url=urljoin(base_url,"origdatablocks/fullquery/"),params=data_block_params,headers=headers,stream=False,verify=True)
            arguments["data_set"]=requests.get(url=urljoin(base_url,"datasets/"+requested_dataset_id),headers=headers,stream=False,verify=True)
        else:
            arguments["event"] = True
            arguments["event_type"] = "alert-danger"
            arguments["event_text"] = "User not allowed to view Data set"
            arguments["data_set"]={}
    else:
        arguments["event"] = True
        arguments["event_type"] = "alert-danger"
        arguments["event_text"] = "No datasets found for users"
        arguments["data_set"]={}
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    return render_template("dataset.html",args=arguments)
@app.route("/createDataset",methods=['POST'])
def createDataset():
    arguments = {}
    ## create Scicat client
    scicat = ScicatClient(base_url="https://mf-scicat.lbl.gov/api/v3",username=os.getenv("usr"),password=os.getenv("pw"))
    ## create MF Admin client infromation 
    user_session = UserSession(flask.session)
    hidden_key = open(".secrets/MF-Hub-key").read().strip()
    orcid = user_session.userinfo["sub"]
    uuidNumber = uuid7()
    persistent_id= "TMF/"+base58.b58encode(uuidNumber.bytes).encode()
    ###GET MFPs
    mfpUrlString = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser-simple.aspx?key={hidden_key}&orcid={orcid}"
    ## get authrorized pids
    mfpResponse = requests.get(url = mfpUrlString)
    mfpList = list(mfpResponse.json())
    ## get form data
    formData = request.form
    mfpFromForm =str(formData["ProposalID"]).strip('"')
    ###GET USER DATA
    userinfoUrl = f"https://foundry-admin.lbl.gov/api/JSON/PsyCat-GetUser.aspx?key={hidden_key}&orcid={orcid}"
    userInfoResponse = requests.get(url=userinfoUrl)
    userInfo = userInfoResponse.json()[0]
    dataPlinthUser = user()
    dataPlinthUser.first_name = userInfo["first_name"]
    dataPlinthUser.last_name = userInfo["last_name"]
    dataPlinthUser.email = userInfo["email"]
    dataPlinthUser.lbl_email = userInfo["lbl_email"]
    dataPlinthUser.orcid = orcid
    ##### create Data
    if mfpFromForm in mfpList:
        if 'thumbnailFile' not in request.files or "h5FileValue" not in request.files:
            arguments["event"] = True
            arguments["event_type"] = "alert-danger"
            arguments["event_text"] =""#make blank so we can ask for it in the next step
            if "thumbnailFile" not in request.files:
                arguments["event_text"] = arguments["event_text"] + "No Thumnail picture provided"
            if "h5FileValue" not in request.files:
                arguments["event_text"] = arguments["event_text"] + "No h5file picture provided"
            arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
            encodedURl = "?"+urlencode(arguments)
            return redirect("/data-input"+encodedURl)
        thumbnailFile = request.files['thumbnailFile']
        h5File = request.files["h5FileValue"]
        if h5File.filename == '':
            arguments["event"] = True
            arguments["event_type"] = "alert-danger"
            arguments["event_text"] ="No file name in h5 file"
            arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
            encodedURl = "?"+urlencode(arguments)
            return redirect("/data-input"+encodedURl)
        if (thumbnailFile and allowed_file(thumbnailFile.filename)) and (thumbnailFile and allowed_file(h5File.filename)):
            directoryPath =os.path.join(app.config['UPLOAD_FOLDER'], f"{mfpFromForm}/")
            thumbnailFilename = f"{directoryPath}{str(uuid.uuid4())}-{secure_filename(thumbnailFile.filename)}"
            h5Filename = f"{directoryPath}{str(uuid.uuid4())}-{secure_filename(h5File.filename)}" 
        if not os.path.exists(directoryPath):
            os.makedirs(directoryPath)
        
        thumbnailFile.save(thumbnailFilename)
        h5File.save(h5Filename)
        #reassigning to the h5py h5File
        h5File = h5py.File(h5Filename)
        #ownable = Ownable(ownerGroup=str(mfpFromForm), accessGroups=[str(mfpFromForm)])
        mfF5Decoder = MF_Hdf5_Decoder(h5File)
        mfF5Decoder.h5File.visititems(mfF5Decoder.decode)
        scientificMetadataDict = json.loads(mfF5Decoder.dumps())
        dataset = RawDataset(
            pid=persistent_id,
            ownerGroup="Admin",    #Needed
            description=formData["desciptionValue"], #Optional
            owner=orcid, #needed
            orcidOfOwner=orcid, #optional
            principalInvestigator = dataPlinthUser.fullname() ,#Needed
            contactEmail= dataPlinthUser.email, #Needed
            creationLocation="Moleculor Foundry", 
            type="raw", #Needed
            sourceFolder=directoryPath,#sourceFolder=directoryPath,##Needed 
            scientificMetadata = scientificMetadataDict,
            accessGroups=[mfpFromForm],
            creationTime=datetime.datetime.now().isoformat(),#Needed
            )
        dataset_id = scicat.datasets_create(dataset)["pid"]
        h5data_file = DataFile(path=h5Filename, size=os.path.getsize(h5Filename),time = datetime.datetime.now().isoformat())
        listOfH5Files = []
        listOfH5Files.append(h5data_file)
        totalSizeOfFiles= 0
        for h5Fileindex in listOfH5Files:
            totalSizeOfFiles = totalSizeOfFiles + os.path.getsize(h5Fileindex.path)
        data_block = OrigDatablock(size=totalSizeOfFiles,
            ownerGroup="Admin",    
            version="1",
            datasetId=dataset_id,
            dataFileList=listOfH5Files)
        scicat.datasets_origdatablock_create(data_block) 

        
        attachment = Attachment(
            ownerGroup=mfpFromForm,
            datasetId=dataset_id,
            thumbnail=encode_thumbnail(thumbnailFilename),
            caption="Thumnail Image",
            )
        scicat.upload_attachment(attachment,datasetType="datasets")
    arguments["event"] = True
    arguments["event_type"] = "alert-sucess"
    arguments["event_text"] =f"Dataset created with id {dataset_id}"
    arguments = argumentHandler(requestArguments=request.args,newArguments=arguments)
    encodedURl = "?"+urlencode(arguments)    
    return redirect("/profile")
@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
auth.init_app(app)

UPLOAD_FOLDER = './static/images/datasetImages/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',"h5"])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.run(host="data-plinth-flask-backend",debug=True)
