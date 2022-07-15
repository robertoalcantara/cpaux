# coding: utf-8

import json
from flask import Flask
from flask import make_response
from flask import request
from flask import abort
from CPMgmt import CPApi
from threading import Thread
from threading import Event
import time

'''
Start the API and provides json via web
Sample request:  GET http://127.0.0.1:5000/?k=xxxxxthujIgLqyFwt6w/w==
'''

SERVER = "192.168.0.100" 
KEY_FILE = ".cpkey.txt"
WEBKEY_FILE = ".webkey.txt"
CACHE_TIME = 30 #s

app = Flask(__name__)
cpApiKey = ""
webKey = ""
cp = None
updated = None

@app.route("/")
def data( ):
    global updated
    global cp
    
    key = request.args.get('k')
    if key != webKey:
        time.sleep(5) #throttle against brute force
        abort(403)
    
    updated.wait() #wait update running

    jdata = " { \"rulebases\" : ["
    for rulebase in cp.rulebases.values():
        jdata = jdata + rulebase.toJSON() + ','
    jdata = jdata[:-1]
    jdata = jdata +  ']}'

    r = make_response( jdata )
    r.mimetype = 'application/json'
    return r                    


def update():
    global updated
    global cp
    while True:
        updated.clear()
        cp = CPApi( SERVER, cpApiKey, noSSL=True, rulebases_names=['inside_access_in_opt','dmz_access_in_opt'] )
        updated.set()
        time.sleep(CACHE_TIME)
    

if __name__ == "__main__":

    f = open(KEY_FILE) # WEB API Key do CP
    cpApiKey = f.read()
    f.close()

    f = open(WEBKEY_FILE) # web key to request this content
    webKey = f.read()
    f.close()

    updated = Event()

    updateTask = Thread(target=update)
    updateTask.start()

    app.run(debug=False, host='0.0.0.0' , port=5000) 
    