from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/users/validate'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401


@app.before_request
def before_request_callback():
    endPoint = cleanURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        user = get_jwt_identity()
        print(user)
        if user["rol"] is not None:
            hasPermission = validatePermission(endPoint, request.method, user["rol"]["_id"])
            print(hasPermission)
            if not hasPermission:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401


def cleanURL(url):
    parts = url.split("/")
    for part in parts:
        if re.search('\\d', part):
            url = url.replace(part, "?")
    return url


def validatePermission(endpoint, method, id_role):

    print(endpoint, method, id_role)

    url = dataConfig["url-backend-security"] + "/permission-rol/validate-permission/role/" + str(id_role)
    havePermission = True
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endpoint,
        "method": method
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if "_id" in data:
            havePermission = True
    except:
        pass
    return havePermission


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


###################################################################################
@app.route("/mesas", methods=['GET'])
def getTables():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesas'
    response = requests.get(url, headers=headers)
    jsonT = response.json()
    return jsonify(jsonT)


@app.route("/mesas", methods=['POST'])
def createTable():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesas'
    response = requests.post(url, headers=headers, json=data)
    jsonT = response.json()
    return jsonify(jsonT)


@app.route("/mesas/<string:_id>", methods=['GET'])
def getTableByID(_id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesas' + _id
    print(url)
    response = requests.get(url, headers=headers)
    jsonT = response.json()
    return jsonify(jsonT)


@app.route("/mesas/<string:_id>", methods=['PUT'])
def editTable(_id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesas' + _id
    response = requests.put(url, headers=headers, json=data)
    jsonT = response.json()
    print(jsonT)
    return jsonify(jsonT)


@app.route("/mesas/<string:_id>", methods=['DELETE'])
def deleteTable(_id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-academic"] + '/mesas' + _id
    response = requests.delete(url, headers=headers)
    jsonT = response.json()
    print(jsonT)
    return jsonify(jsonT)


if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
