from flask import Flask, render_template,abort,request
import requests
import os

app = Flask(__name__)
key=os.environ["ShodanKey"]
payload={'key':key}
webscan_base="https://api.shodan.io/shodan/"
vuln_base="https://exploits.shodan.io/api/search?query="

@app.route('/', methods=["GET"])
def inicio():
    return render_template('inicio.html')

app.run(debug=True)