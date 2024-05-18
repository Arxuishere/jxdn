from flask import * 

import json, datetime, re

import requests

import paramiko

import threading

from flask import Blueprint, jsonify, request

from funcs.string import str_equals, is_str_empty, sanitize, str_validation



Admin = Blueprint("Admin", __name__)



@Admin.route("/admin/addkey", methods=["GET"])

def index_addkey():

    if 'adminkey' in request.args and 'keyname' in request.args and 'expired' in request.args and 'maxtime' in request.args and 'maxconc' in request.args:

        adminkey = sanitize(request.args.get('adminkey', default=None, type=str))

        keyname = sanitize(request.args.get('keyname', default=None, type=str))

        expired = sanitize(request.args.get('expired', default=None, type=str))

        maxtime = sanitize(request.args.get('maxtime', default=None, type=str))

        maxcons = sanitize(request.args.get('maxconc', default=None, type=str))

    else:

        return jsonify({"response_message": "Missing argument(s)."})

    

    if not all([adminkey, keyname, expired, maxtime, plans, maxcons]):

        return jsonify({"response_message": "Missing argument(s). Null values."})

    

    with open("./data/database.json") as e:

        db = json.load(e)

    

    with open("./data/admin_key.json") as e:

        admkey = json.load(e)



    if str_validation(adminkey):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(keyname):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(expired):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(maxtime):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(plans):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(maxcons):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if not maxtime.isdigit():

        return jsonify({"response_message": "Maxtime must digit."})

    

    if not maxcons.isdigit():

        return jsonify({"response_message": "Maxconc must digit."})

    

    if not maxtime.isdigit():

        return jsonify({"response_message": "Curconc cmust digit."})

    

    if re.match(r'^\d{4}-\d{2}-\d{2}$', expired):

        return jsonify({"response_message": "Format must YEAR-MONTH-DAY, ex: 2045-12-2."})

    else:

        expired = expired



    if adminkey not in admkey['keys']:

        return jsonify({"response_message": "Key invalid."})

    

    try:

        db["keys"][keyname]= {"exp": expired, "maxTime": maxtime, "maxCons": maxcons, "curCons": 0}

        with open("./data/database.json", "w") as json_file:

            json.dump(db, json_file, indent=4)

        return jsonify({"response_message": "Data successfully added."})

    except Exception as e:

        return jsonify({"response_message": "An error occurred."})

        print(e)



@Admin.route("/admin/deletekey", methods=["GET"])

def index_deleted_key():

    if 'adminkey' in request.args and 'keyname' in request.args:

        adminkey = sanitize(request.args.get('adminkey', default=None, type=str))

        keyname = sanitize(request.args.get('keyname', default=None, type=str))

    else:

        return jsonify({"response_message": "Missing argument(s)."})

    

    if not all([adminkey, keyname]):

        return jsonify({"response_message": "Missing argument(s). Null values."})

    

    with open("./data/database.json") as e:

        db = json.load(e)

    

    with open("./data/admin_key.json") as e:

        admkey = json.load(e)



    if str_validation(adminkey):

        return jsonify({"response_message": "Error, Malcious character detected."})

    

    if str_validation(keyname):

        return jsonify({"response_message": "Error, Malcious character detected."})



    if adminkey not in admkey['keys']:

        return jsonify({"response_message": "Key invalid."})

    

    try:

        del db["keys"][keyname]

        with open("./data/database.json", "w") as json_file:

            json.dump(db, json_file, indent=4)

        return jsonify({"response_message": "Data successfully deleted."})

    except Exception as e:

        return jsonify({"response_message": "An error occurred."})

        print(e)

        

@Admin.route("/admin/addservers", methods=["GET"])

def index_add_server():

  if 'adminkey' in request.args and 'hostname' in request.args and 'username' in request.args and 'password' in request.args:

    adminkey = sanitize(request.args.get('adminkey', default=None, type=str))

    hostname = sanitize(request.args.get('hostname', default=None, type=str))

    username = sanitize(request.args.get('username', default=None, type=str))

    password = sanitize(request.args.get('password', default=None, type=str))

  else:

    return jsonify({"response_message": "Missing argument(s)."})

    

  if not all([adminkey, hostname, username, password]):

    return jsonify({"response_message": "Missing argument(s). Null values."})

   

  with open("./data/vps_servers.json") as e:

    db = json.load(e)

  

  with open("./data/admin_key.json") as e:

    admkey = json.load(e)

    

  if str_validation(adminkey):

    return jsonify({"response_message": "Error, Malcious character detected."})

  

  if adminkey not in admkey['keys']:

    return jsonify({"response_message": "Key invalid."})

  

  try:

    db.append({"hostname": hostname, "username": username, "password": password})

    with open("./data/vps_servers.json", "w") as json_file:

      json.dump(db, json_file, indent=4)

    return jsonify({"response_message": "Add Servers successfully"})

  except Exception as e:

    return jsonify({"response_message": "An error occurred."})

    print(e)



@Admin.route("/admin/help", methods=["GET"])

def index_admin():

    admin_key = request.args.get('key')

    

    if admin_key is None:

        return jsonify({"response_message": "Enter correctly"}), 400

    

    with open("./data/admin.json") as e:

        admkey = json.load(e)

    

    if admin_key not in admkey['keys']:

        return jsonify({"response_message": "Key invalid"}), 400

    

    return jsonify({

        "result": {

            "Help Command": {

              "/admin/addproxy?key=[key]&method=[method]&layer=[layer]&url=[url]\n\n/admin/addserver?key=[key]&hostname=[HOST_NAME]&port=[PORT]&username=[USER_NAME]&password=[PASSWORD]",

              "Proxy Help\nMethod = UA,PROXY\nLayer = 4,7"

            }

        }

    }), 200

    



@Admin.route("/admin/addproxy", methods=["GET"])

def add_proxy_admin():

    admin_key = request.args.get('key')

    method_add = request.args.get('method')

    layer = request.args.get('layer')

    url_add =  request.args.get('url')

    

    if not all([admin_key, method_add, layer, url_add]):

        return jsonify({"response_message": "Enter correctly"}), 400

    

    with open("./data/admin.json") as e:

        admkey = json.load(e)

    

    with open("./data/vps_servers.json") as file:

        ssh_servers = json.load(file)



    if admin_key not in admkey['keys']:

        return jsonify({"response_message": "Key invalid"}), 400

    

    if method_add.upper() not in ["PROXY", "UA"]:

        return jsonify({"response_message": f"invalid to {method_add}"}), 400

    

    if layer.upper() not in ["7", "4"]:

        return jsonify({"response_message": f"invalid to {method_add}"}), 400

    

    if not url_add.lower().startswith("https://"):

        return jsonify({"response_message": "URL must start with 'https://'"})

    

    def connect_to_ssh_server(server):

        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:

            ssh.connect(server['hostname'], port=server['port'], username=server['username'], password=server['password'])

        except paramiko.AuthenticationException:

            print(f"Failed to connect to {server['hostname']} - Authentication failed")

            return False

        except paramiko.SSHException as e:

            print(f"Failed to connect to {server['hostname']} - {str(e)}")

            return False

        except Exception as e:

            print(f"Error connecting to {server['hostname']} - {str(e)}")

            return False

        

        if method_add.upper() not in ['PROXY', 'UA']:

            print(f"Invalid method parameter: {method_add}")

            return False



        if layer.upper() not in ['4', '7']:

            print(f"Invalid layer parameter: {layer}")

            return False

            

        if method_add.upper() == 'PROXY':

            if layer.upper() == "7":

                print(f"[BOTS] {server['hostname']} -> Add Proxy to layer7")

                command = f"cd /root/methods/layer7/ && rm -rf proxy.txt && wget {url_add}"

            elif layer.upper() == "4":

                print(f"[BOTS] {server['hostname']} -> Add Proxy to layer4")

                command = f"cd /root/methods/layer4/ && rm -rf proxy.txt && wget {url_add}"

        elif method_add.upper() == 'UA':

            if layer.upper() == "7":

                print(f"[BOTS] {server['hostname']} -> Add Useragent to layer7")

                command = f"cd /root/methods/layer7/ && rm -rf ua.txt && wget {url_add}"

            elif layer.upper() == "4":

                print(f"[BOTS] {server['hostname']} -> Add Useragent to layer4")

                command = f"cd /root/methods/layer4/ && rm -rf ua.txt && wget {url_add}"

            

        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode('utf-8')

        ssh.close()

        return True

    

    threads = []

    for server in ssh_servers:

        thread = threading.Thread(target=connect_to_ssh_server, args=(server,))

        thread.start()

        threads.append(thread)



    for thread in threads:

        thread.join()

    

    return jsonify({

        "result": {

            "Successfull Add": {

                "method": method_add,

                "layer": layer,

                "url_add": url_add

            }

        }

    }), 200
