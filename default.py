from flask import Flask, render_template,abort,request
import requests
import os
import random
import re

app = Flask(__name__)
key=os.environ["ShodanKey"]
hbp=os.environ["HBPKey"]
payload={'key':key}
webscan_base="https://api.shodan.io/shodan/"
vuln_base="https://exploits.shodan.io/api/search?query="
session=requests.session()
baseAPIURL = "https://haveibeenpwned.com/api/v3/"
headers={"hibp-api-key": hbp}

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

    
    ipcam1='95.124.44.163'
    ipinfo1=session.get(webscan_base+'host/'+ipcam1,params=payload)
    ipcam2='83.48.82.34'
    ipinfo2=session.get(webscan_base+'host/'+ipcam2,params=payload)
    return render_template('inicio.html', randomip=randomip, answer=ipinfo.json(), ipcam1=ipcam1, ipcam2=ipcam2, answer1=ipinfo1.json(), answer2=ipinfo2.json())

@app.route('/hostscan/', methods=["GET","POST"])
def hostscan():
    filter=session.get("https://beta.shodan.io/search/filters").text
    query=re.findall(r'<li>(.*?)</li>',str(filter))
    filtro=request.form.get("query")
    filtrado=request.form.get("filtrado")
    if request.method=="GET":
        return render_template('hostscan.html', query=query, filtro=filtro, filtrado=filtrado)
    else:
        r=session.get(webscan_base+"host/search?query="+filtro+":"+filtrado, params=payload)
        respuesta=r.json()
        respuestas=[]
        for ips in respuesta["matches"]:
            ip_list=ips["ip_str"]
            respuestas.append(ip_list)
        
        return render_template('hostscan.html', query=query, filtro=filtro, filtrado=filtrado, respuestas=respuestas)

@app.route('/host/<string:ip>', methods=["GET"])
def host(ip):
    host=session.get(webscan_base+"host/"+ip, params=payload)
    respuesta=host.json()
    ippag=respuesta["ip_str"]
    if ippag == ip:
        return render_template('host.html',respuesta=respuesta, ippag=ippag)

@app.route('/pwned/', methods=["GET","POST"])
def pwdned():
    query=['breachedaccount', 'pasteaccount']
    filtro=request.form.get("query")
    print(filtro)
    email=request.form.get("email")
    print(email)
    if request.method=="GET":
        return render_template('pwned.html', query=query, filtro=filtro, email=email)
    else:
        urlEndpoint = filtro+'/'+email
        urlToFetch = baseAPIURL+urlEndpoint
        r = session.get(urlToFetch, verify=True, headers=headers)
        if r.status_code==200:
            if filtro=='breachedaccount':
                response=r.json()
                return render_template('pwned.html', query=query, filtro=filtro, email=email, response=response)
            else:
                paste=r.json()
                return render_template('pwned.html', query=query, filtro=filtro, email=email, paste=paste)
        else:
            response="No se ha encontrado ninguna brecha en el email: "+email
            return render_template('pwned.html', filtro=filtro, query=query, email=email, respuesta=response)

@app.route('/busqueda/', methods=["GET"])
def busqueda():
    return render_template('busqueda.html')

@app.route('/actualizar/<string:ip>', methods=["GET"])
def actualizar(ip):
    data={
    'ips': ip
    }
    update=session.post(webscan_base+'scan?+ips=', data=ip, params=payload)
    return render_template('scan.html', ip=ip)

port=os.environ["PORT"]
app.run('0.0.0.0', int(port), debug=True)