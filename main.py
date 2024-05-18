# Code by Jxdn
from flask import *
from waitress import serve
from threading import Thread
import logging, json, os, time, paramiko
from colorama import Fore, init
from routes.admin_routes import Admin
from routes.attack_routes import Attack

app = Flask(__name__, None, "static")

app.register_blueprint(Attack)
app.register_blueprint(Admin)

def check_vps_connection(vps_address, username, password):
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(vps_address, username=username, password=password)
    ssh.close()
    return True
  except Exception as e:
    return str(e)
        
with open("./data/vps_servers.json") as file:
  vps_list = json.load(file)
        
@app.route('/')
def indexpage():
    return render_template('index.html')

@app.errorhandler(404)
def error_404(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def error_500(e):
    return render_template('500.html'), 500
    
if __name__ == "__main__":
    os.system('clear')
    init()
    print(Fore.WHITE, """
▒█░░░ █▀▀█ █▀▀ ▀▀█▀▀ 　 ░█▀▀█ ▒█▀▀█ ▀█▀ 
▒█░░░ █░░█ ▀▀█ ░░█░░ 　 ▒█▄▄█ ▒█▄▄█ ▒█░ 
▒█▄▄█ ▀▀▀▀ ▀▀▀ ░░▀░░ 　 ▒█░▒█ ▒█░░░ ▄█▄
""", Fore.RESET)
    print(Fore.MAGENTA, "Code by Jxdn", Fore.RESET)
    print(Fore.BLUE, "Lost API official servers started.", Fore.RESET)
    connected_count = 0
    for vps in vps_list:
      vps_connection_status = check_vps_connection(vps['hostname'], vps['username'], vps['password'])
      if vps_connection_status == True:
        connected_count += 1
      else:
        print(Fore.RED, f"[Warning] Hostname {vps['hostname']} failed to connect", Fore.RESET)
    print(f"[System] Total servers connect : {connected_count}")
    serve(app, host="0.0.0.0", port=8080)