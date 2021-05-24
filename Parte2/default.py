from flask import Flask, render_template,abort,request
import requests
import os
import random
import re
import pdb

app = Flask(__name__)
key=os.environ["ShodanKey"]
payload={'key':key}
webscan_base="https://api.shodan.io/shodan/"
vuln_base="https://exploits.shodan.io/api/search?query="
session=requests.session()

@app.route('/', methods=["GET"])
def inicio():
    r=session.get(webscan_base+'host/search?&query=country:es city:"Sevilla" port:"3389" has_screenshot:1 -screenshot.label:blank',params=payload)
    r.raw.chunked=True
    r.encoding='utf-8'
    response=r.json()
    ips=[]
    for i in response["matches"]:
        ips.append(i["ip_str"])

    randomip=random.choice(ips)
    ipinfo=session.get(webscan_base+'host/'+randomip,params=payload)

    cam=session.get(webscan_base+'host/search?query=port:554 country:es has_screenshot:1 -screenshot.label:blank',params=payload)
    cam.raw.chunked=True
    cam.encoding='utf-8'
    respuesta=cam.json()
    ipcam=[]
    for camera in respuesta["matches"]:
            ip_list=camera["ip_str"]
            ipcam.append(ip_list)

    randomcamip1=random.choice(ipcam)
    ipinfo1=session.get(webscan_base+'host/'+randomcamip1,params=payload)
    
    randomcamip2=random.choice(ipcam)
    ipinfo2=session.get(webscan_base+'host/'+randomcamip2,params=payload)
    return render_template('inicio.html', randomip=randomip, answer=ipinfo.json(), randomcamip=randomcamip1, randomcamip2=randomcamip2, answer1=ipinfo1.json(), answer2=ipinfo2.json())

@app.route('/hostscan/', methods=["GET","POST"])
def hostscan():
    filter=session.get("https://beta.shodan.io/search/filters").text
    query=re.findall(r'<li>(.*?)</li>',str(filter))
    return render_template('hostscan.html', query=query)

app.run(debug=True)