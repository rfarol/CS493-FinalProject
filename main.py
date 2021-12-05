# boostrap cdn taken from: https://cdn.jsdelivr.net/npm/bootswatch@4.5.2/dist/cosmo/bootstrap.min.css
# code implentation taken from: https://developers.google.com/identity/protocols/oauth2/web-server
# JWT ID token implentation is taken from: https://developers.google.com/identity/sign-in/web/backend-auth
# skeleton code taken from HTTP/REST Implentation 

from google.cloud import datastore
from google.oauth2 import id_token
from google.auth.transport import requests as jwt_request 
import flask
from flask import Flask, request, render_template
import json
import requests
import uuid
import random
import constants

app = flask.Flask(__name__)
app.secret_key = str(uuid.uuid4())
app.debug = True
client = datastore.Client()


CLIENT_ID = '492758256631-aq1l5n6hb9fmteqpq66ln2f0v3g524id.apps.googleusercontent.com'
CLIENT_SECRET = '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'
SCOPE = 'https://www.googleapis.com/auth/userinfo.profile'
REDIRECT_URI = 'https://cs493hw7-farolr.wl.r.appspot.com/oauth'
# local REDIRECT_URI = 'http://localhost:8080/oauth'
STATE = "State" + str(random.randint(1, 9999999)) # randomize state 

# get sub from JWT
def get_sub():
    if 'Authorization' in request.headers:
        user_jwt = request.headers['Authorization'] # request Authorization header 
        user_jwt = user_jwt.replace('Bearer ', '') # delete the "Bearer" string and space in front of the token
        try:
              idinfo = id_token.verify_oauth2_token(user_jwt, jwt_request.Request(), CLIENT_ID)
              sub = idinfo['sub']
              return sub
        except:
            return "Invalid Token"
    else:
        return ("Missing/invalid JWT", 401)

@app.route('/')
def index():
    return render_template('welcome.html')

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
    # post request 
    if request.method == 'POST':
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
        "length": content["length"], "public": content["public"]})
        owner = get_sub()
        if owner != "Invalid Token":
            new_boat.update({"owner": owner})
            client.put(new_boat)
            boat = client.get(key=new_boat.key)
            boat['id'] = new_boat.key.id
            boat['self'] = request.url + "/" + str(new_boat.key.id) # add self URL
            return (boat, 201) # boat is returned as a JSON object. 201 request code 
        else:
            return ('Missing/invald JWT', 401) # 401 code if Missing/valid JWT
        
    # get request for all boats 
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url + "/" + str(e.key.id) # add self URL 
        get_boats = []
        owner = get_sub()
        # checks if JWT token has been entered
        if owner != "Invalid Token":
            for e in results:
                if e["owner"] == owner:
                    get_boats.append(e)
        # if no JWT token is entered, all public boats are returned
        if 'Authorization' not in request.headers:
            for e in results:
                if e["public"] == "True":
                    get_boats.append(e)
        return (json.dumps(get_boats), 200)
    else:
        return ('Method not recognized')
    

@app.route('/owners/<id>/boats', methods=['GET'])
def owners_get(id):
    if request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        owners_list = []
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url + "/" + str(e.key.id) # add self URL
            # checks if owner ID matches and if boats are public  
            if e["public"] == "True" and e["owner"] == id:
                owners_list.append(e)
        return (json.dumps(owners_list), 200)
    else:
        return ('Method not recognized')  


@app.route('/boats/<id>', methods=['DELETE'])
def boats_delete(id):
    # delete request to delete a specific boat 
    if request.method == 'DELETE':
        owner = get_sub()
        if owner != "Invalid Token":
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat is not None:
                # check if owner id matches 
                if boat["owner"] == owner:
                    client.delete(boat_key)
                    return ('Boat was deleted', 204) # Boat was successfully deleted. 204 request. 
                else:
                    return ("This boat belongs to someone else, please only delete boats that you own", 403) # doesn't delete due to different ID
            else:
                return ("This boat ID does not exist. Please try again.", 404) # wrong ID is entered 
        else:
            return ('Missing/invald JWT', 401) # JWT is invalid or missing 
    else:
        return ('Method not recognized')
    

@app.route('/userinfo')
def userinfo():
    # store date into datastore
    new_state = datastore.Entity(client.key("states"))
    new_state.update({'state': STATE})
    client.put(new_state)
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('oauth'))
    credentials = json.loads(flask.session['credentials'])
    if credentials['expires_in'] <= 0:
        return flask.redirect(flask.url_for('oauth'))
    else:
        credentials = json.loads(flask.session['credentials'])
        try:
            id_token.verify_oauth2_token(credentials['id_token'], jwt_request.Request(), CLIENT_ID)
            return render_template('userinfo.html', jwt_var=credentials['id_token'])
        except:
            return ("Missing/invalid JWT", 401) 

@app.route('/oauth')
def oauth():
    if 'code' not in flask.request.args:
        authorization_uri = ('https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}').format(CLIENT_ID, REDIRECT_URI, SCOPE, STATE)
        return flask.redirect(authorization_uri)
    else:
        authorization_code = flask.request.args.get('code')
        data = {'code': authorization_code, 'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'redirect_uri': REDIRECT_URI, 'grant_type': 'authorization_code', 'State': STATE}
        # fetch all the states stored within the datastore 
        query = client.query(kind="states")
        results = list(query.fetch())
        for i in results:
           if i['state'] == STATE:
            request = requests.post('https://oauth2.googleapis.com/token', data=data)
            flask.session['credentials'] = request.text
            return flask.redirect(flask.url_for('userinfo'))
        else:
            return ("State is invalid")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)