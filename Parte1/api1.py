#!/usr/bin/python3
import requests
import os
import json
import pdb
key=os.environ.get("ShodanKey")

def Menu():
    print("Menú Shodan")
    print("1. Filtrar por IP\n2. Escaneo de Puertos\n3. Escaneo de Protocolos\n4. Salir")

Menu()
opcion=int(input("Elige una opción: "))
while opcion != 4:
    if opcion == 1:
        host = requests.get(f"https://api.shodan.io/shodan/host/8.8.8.8?key={key}")
        print(host.json())
        opcion=int(input("Elige una opción: "))
    
    elif opcion == 2:
        ports=requests.get(f"https://api.shodan.io/shodan/ports?key={key}")
        print(ports.json())
        opcion=int(input("Elige una opción: "))
    
    elif opcion == 3:
        protocols=requests.get(f"https://api.shodan.io/shodan/protocols?key={key}")
        print(protocols.json())
        opcion=int(input("Elige una opción: "))