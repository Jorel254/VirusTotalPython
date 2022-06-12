from cgitb import text
from contextlib import nullcontext
import json
from multiprocessing import Pipe
import os
from tkinter.font import families
import requests
import time
import sys
from tkinter import *
from tkinter.filedialog import askdirectory, askopenfilename
import subprocess
import platform
import re
from dataclasses import replace
from multiprocessing.dummy import current_process
from trace import Trace
import psutil
from tabulate import tabulate
file_path=""
CuerrentSystem = platform.system()
menuprincipal= int (input("Menu de análisis \n 1-Buscar sample \n 2-Analizar mediante hash \n 3-Subir archivo para análisis \n 4-Ver reporte del análisis \n 5-análisis con Viper subir archivo \n 6-Reporte de análisis con Viper\n 7-análisis con Cuckoo  \n 8-Salir \n"))  
while menuprincipal!=8:
    if menuprincipal ==1:
        #Buscar sample
        print("Selecciona un archivo")
        root = Tk()
        root.withdraw()
        root.update()
        file_path = askopenfilename()
        print(file_path)
        time.sleep(3)
        root.destroy()
    elif menuprincipal ==2:
        #Analizar mediante hash
        print("Iniciando análisis")
        if file_path != "":
            HashFile=""
            FinalHash=""
            fullpath=""
            temp= file_path.split('/')
            last = temp.pop()
            contador= 1
            for ele in temp:  
                if contador < len(temp):
                    fullpath += ele +'/'
                    contador = contador +1
                else:
                    fullpath += ele   
            if CuerrentSystem =="Windows":
                HashFile = subprocess.check_output('certutil -hashfile '+ file_path + ' SHA256',shell=True).decode(sys.stdout.encoding).strip()
                x=re.search("[A-Fa-f0-9]{64}",HashFile)
                HashFile = x.group()
            elif CuerrentSystem =="Linux":
                HashFile = subprocess.check_output('sha256sum  '+ file_path,shell=True).decode(sys.stdout.encoding).strip()
                FinalHash = HashFile.split(' ')
                HashFile = FinalHash[0]
            elif CuerrentSystem == "Darwin":
                HashFile = subprocess.check_output('shasum -a 256  "'+ file_path+'"',shell=True).decode(sys.stdout.encoding).strip()
                x=re.search("[A-Fa-f0-9]{64}",HashFile)
                HashFile = x.group()
            else:
                print(CuerrentSystem)
                exit;
        else:
            HashFile = input("Inserte el hash para el análisis \n");

        print("El hash del archivo es: " + HashFile)
        api_url = 'https://www.virustotal.com/api/v3/files/'+ HashFile
        headers = {'x-apikey' : ""}#Insert your API key here !!!!!
        response = requests.get(api_url, headers=headers)
        if (response.status_code != 200):
            print("Not found sample")
            input();
        else:
            response_jason= json.loads(response.text)
            documentText = response_jason['data']
            Tipo=documentText['attributes']['type_description']
            Tlsh=documentText['attributes']['tlsh']
            print("\n")
            print("Atributos de la muestra")
            d=[[Tipo,Tlsh]]
            print(tabulate(d, headers=["Type","Tlsh"]))
            trid=documentText['attributes']['trid']
            d=[[]]
            for item in trid:
                file_type=item['file_type']
                probability=item['probability']
                d.append([file_type,probability])
            print("\n")
            print("Trid")
            print(tabulate(d, headers=["file_type", "probability"]))
            names=documentText['attributes']['names']
            d=[[]]
            for item in names:
                Name=item
                d.append([Name])
            print("\n")
            print("Nombres de la muestra")
            print(tabulate(d, headers=["Name"]))
            analisis=documentText['attributes']['last_analysis_results']
            d=[[]]
            for item in analisis:
                Name=item
                category=item['category']
                engine_name=item['engine_name']
                engine_version=item['engine_version']
                result=item['result']
                method=item['method']
                engine_update=item['engine_update']
                d.append([Name,category,engine_name,engine_version,result,method,engine_update])
            print("\n")
            print("Nombres de la muestra")
            print(tabulate(d, headers=["Name","category","engine_name","engine_version","result","method","engine_update"]))
            input()
    elif menuprincipal ==3:
        #Subir archivo para análisis
        print("Selecciona un archivo para analizar")
        root = Tk()
        root.withdraw()
        root.update()
        file_path = askopenfilename()
        root.destroy()
        api_url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey' : ""} #Insert your API key here !!!!!
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(api_url, headers=headers, files=files)
        if (response.status_code != 200):	
            print("Not found sample")	
        else:
            response_jason= json.loads(response.text)
            documentText = response_jason['data']
            print("ID del escaneo: " + documentText['id']) 
            Tipo=documentText['attributes']['type_description']
            Tlsh=documentText['attributes']['tlsh']
            print("\n")
            print("Atributos de la muestra")
            d=[[Tipo,Tlsh]]
            print(tabulate(d, headers=["Type","Tlsh"]))
            trid=documentText['attributes']['trid']
            d=[[]]
            for item in trid:
                file_type=item['file_type']
                probability=item['probability']
                d.append([file_type,probability])
            print("\n")
            print("Trid")
            print(tabulate(d, headers=["file_type", "probability"]))
            names=documentText['attributes']['names']
            d=[[]]
            for item in names:
                Name=item
                d.append([Name])
            print("\n")
            print("Nombres de la muestra")
            print(tabulate(d, headers=["Name"]))
        input()  
    elif menuprincipal == 4:
        #Ver reporte del análisis
        print("Inserte el ID del escaneo del cual quiero obtener informacion")   
        ID=input()
        url = "https://www.virustotal.com/api/v3/files/" +  ID
        headers = {"Accept": "application/json"}
        response = requests.request("GET", url, headers=headers)
        if (response.status_code != 200):
            print("Not found sample")
            input();
        else:
            response_jason= json.loads(response.text)
            documentText = response_jason['data']
            Tipo=documentText['attributes']['type_description']
            Tlsh=documentText['attributes']['tlsh']
            print("\n")
            print("Atributos de la muestra")
            d=[[Tipo,Tlsh]]
            print(tabulate(d, headers=["Type","Tlsh"]))
            trid=documentText['attributes']['trid']
            d=[[]]
            for item in trid:
                file_type=item['file_type']
                probability=item['probability']
                d.append([file_type,probability])
            print("\n")
            print("Trid")
            print(tabulate(d, headers=["file_type", "probability"]))
            names=documentText['attributes']['names']
            d=[[]]
            for item in names:
                Name=item
                d.append([Name])
            print("\n")
            print("Nombres de la muestra")
            print(tabulate(d, headers=["Name"]))
            print(documentText)
    elif menuprincipal == 5:
        #análisis con Viper subir archivo
        print("análisis con Viper") 
        if CuerrentSystem =="Linux":
            subprocess.run("cd ~/Desktop/viper", shell=True)
            print("Selecciona un archivo")
            root = Tk()
            root.withdraw()
            root.update()
            file_path = askopenfilename()
            root.destroy()
            a=subprocess.Popen("viper -f " + "'"+file_path+"'",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            a.stdin.write('store\n'.encode('utf-8'))
            a.stdin.write('info\n'.encode('utf-8'))
            a.stdin.write('quit\n'.encode('utf-8'))
            a.stdin.flush()
            a.wait()
            print(a.stdout.read().decode())
        elif CuerrentSystem =="Windows":
            print("Selecciona un archivo")
            root = Tk()
            root.withdraw()
            root.update()
            file_path =askopenfilename()
            root.destroy()
            file_path = file_path.replace("C:","c")
            file_path = "/mnt/" + file_path
            a=subprocess.Popen("wsl", shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE) 
            print(a.communicate(input=('viper\n\ropen -f '+file_path+' \n\rstore\n\info\n\rexit\n\rexit\n\r').encode('utf-8'))[0].decode())   
            a.wait()
        input()
    elif menuprincipal == 6:
        #Reporte de análisis con Viper
        os.system ("clear") 
        print("Buscar escaneo de Viper") 
        option= int(input("Menu \n 1- Buscar todos \n 2- Buscar ultima muestra \n 3- Buscar por nombre \n 4- Buscar por md5 \n 5- Salir\n" ))
        while option!=5:
            if(option == 1):
                if CuerrentSystem =="Linux":
                    a=subprocess.Popen("viper  ",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
                    a.stdin.write('find all\n'.encode('utf-8'))
                    a.stdin.write('quit\n'.encode('utf-8'))
                    a.stdin.flush()
                    a.wait()
                    print(a.stdout.read().decode())
                elif CuerrentSystem =="Windows":
                        a=subprocess.Popen("wsl", shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE) 
                        print(a.communicate(input=('viper\n\r'+' \n\rfind all\n\rexit\n\rexit\n\rexit\n\r').encode('utf-8'))[0].decode())   
                        a.wait()
                input()
            elif(option == 2):
                if CuerrentSystem =="Linux":
                    a=subprocess.Popen("viper  ",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
                    a.stdin.write('find latest\n'.encode('utf-8'))
                    a.stdin.write('quit\n'.encode('utf-8'))
                    a.stdin.flush()
                    a.wait()
                    print(a.stdout.read().decode())
                elif CuerrentSystem =="Windows":
                        a=subprocess.Popen("wsl", shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE) 
                        print(a.communicate(input=('viper\n\r'+' \n\rfind latest\n\rexit\n\rexit\n\r').encode('utf-8'))[0].decode())   
                        a.wait()
                input()
            elif(option == 3):
                if CuerrentSystem =="Linux":
                    print("Ingresa el nombre de la muestra") 
                    name = input()
                    findsample='find name ' + name +'\n'
                    a=subprocess.Popen("viper  ",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
                    a.stdin.write(findsample.encode('utf-8'))
                    a.stdin.write('quit\n'.encode('utf-8'))
                    a.stdin.flush()
                    a.wait()
                    print(a.stdout.read().decode())
                elif CuerrentSystem =="Windows":
                        print("Ingresa el nombre de la muestra") 
                        name = input()
                        findsample='find name ' + name +'\n'
                        a=subprocess.Popen("wsl", shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE) 
                        print(a.communicate(input=('viper\n\r'+findsample+' \n\rexit\n\rexit\n\r').encode('utf-8'))[0].decode())   
                        a.wait()
                input()
            elif(option == 4):
                if CuerrentSystem =="Linux":
                    print("Ingresa el md5 de la muestra") 
                    md5sample = input()
                    findsample='find md5 ' + md5sample +'\n'
                    a=subprocess.Popen("viper  ",shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
                    a.stdin.write(findsample.encode('utf-8'))
                    a.stdin.write('quit\n'.encode('utf-8'))
                    a.stdin.flush()
                    a.wait()
                    print(a.stdout.read().decode())
                elif CuerrentSystem =="Windows":
                        print("Ingresa el md5 de la muestra") 
                        md5sample = input()
                        findsample='find md5 ' + md5sample +'\n'
                        a=subprocess.Popen("wsl", shell=False,stdin=subprocess.PIPE,stdout=subprocess.PIPE) 
                        print(a.communicate(input=('viper\n\r'+findsample+' \n\rexit\n\rexit\n\r').encode('utf-8'))[0].decode())   
                        a.wait()
                input()
            else:
                print("Escriba una opcion correcta")
            os.system ("clear")
            option= int(input("Menu \n 1- Buscar todos \n 2- Buscar ultima muestra \n 3- Buscar por nombre \n 4- Buscar por md5 \n 5- Salir\n" ))
    elif menuprincipal ==7:
        os.system ("clear") 
        print("Escaneo con Cuckoo ") 
        option= int(input("Menu \n 1- análisis \n 2- Verificar estatus de la muestra \n 3- Obtener reporte \n 4- Resumen del análisis \n 5- Salir\n" ))
        while option!=5:
            if(option == 1):
                print("Selecciona un archivo")
                root = Tk()
                root.withdraw()
                root.update()
                SAMPLE_FILE= askopenfilename()
                print(SAMPLE_FILE)
                time.sleep(3)
                root.destroy()
                REST_URL = "http://localhost:8090/tasks/create/file"
                HEADERS = {"Authorization": "Bearer jon2g"}
                temp= SAMPLE_FILE.split('/')
                last = temp.pop()
                with open(SAMPLE_FILE, "rb") as sample:
                    files = {"file": (last, sample)}
                    response= requests.post(REST_URL, headers=HEADERS, files=files)
                if (response.status_code != 200):
                    print("Report not found or invalid report format")
                    input();
                else:
                    response_jason= json.loads(response.text)
                    task_id = response_jason['task_id']
                print(task_id )
                input()
            elif(option == 2):
                TaskId = input("Inserte el ID de la tarea\n");
                REST_URL = "http://localhost:8090/tasks/view/"+TaskId
                HEADERS = {"Authorization": "Bearer jon2g"}
                response = requests.get(REST_URL, headers=HEADERS)
                if (response.status_code != 200):
                    print("Report not found or invalid report format")
                    input();
                else:
                    response_jason= json.loads(response.text)
                    Status = response_jason['task']['guest']['status']
                    print(Status)
                input()
            elif(option == 3):
                TaskId = input("Inserte el ID de la tarea\n");
                REST_URL = "http://localhost:8090/tasks/report/"+TaskId
                HEADERS = {"Authorization": "Bearer jon2g"}
                response = requests.get(REST_URL, headers=HEADERS)
                if (response.status_code != 200):
                    print("Report not found or invalid report format")
                    input();
                else:
                    response_jason= json.loads(response.text)
                    documentText = response_jason
                    Name=documentText['target']['file']['name']
                    Sha256=documentText['target']['file']['sha256']
                    Tipo=documentText['target']['file']['type']
                    Tam=documentText['target']['file']['size']
                    print("Info de la muestra")
                    d=[[Name,Sha256,Tipo,Tam]]
                    print(tabulate(d, headers=["Name", "Sha256", "Type","Size"]))
                    families=documentText['signatures']
                    d=[[]]
                    for item in families:
                        description=item['description']
                        severity=item['severity']
                        d.append([description,severity])
                    print("\n")
                    print("Signature descriptions")
                    print(tabulate(d, headers=["Description", "Severity"]))
                input()
            elif(option == 4):
                TaskId = input("Inserte el ID de la tarea\n");
                REST_URL = "http://localhost:8090/tasks/summary/"+TaskId
                HEADERS = {"Authorization": "Bearer jon2g"}
                response = requests.get(REST_URL, headers=HEADERS)
                if (response.status_code != 200):
                    print("Report not found or invalid report format")
                    input();
                else:
                    response_jason= json.loads(response.text)
                    documentText = response_jason
                    # Name=documentText['target']['file']['name']
                    # Sha256=documentText['target']['file']['sha256']
                    # Tipo=documentText['target']['file']['type']
                    # Tam=documentText['target']['file']['size']
                    # print("Info de la muestra")
                    # d=[[Name,Sha256,Tipo,Tam]]
                    # print(tabulate(d, headers=["Name", "Sha256", "Type","Size"]))
                    # families=documentText['signatures']
                    # d=[[]]
                    # for item in families:
                    #     description=item['description']
                    #     severity=item['severity']
                    #     d.append([description,severity])
                    # print("\n")
                    # print("Signature descriptions")
                    # print(tabulate(d, headers=["Description", "Severity"]))
                input()
            else:
                print("Escriba una opcion correcta")
            os.system ("clear")
            option= int(input("Menu \n 1- análisis \n 2- Verificar estatus de la muestra \n 3- Obtener reporte \n 4- Resumen del análisis \n 5- Salir\n" ))
    else:
        print("Escriba una opcion correcta")
    os.system ("clear")    
    menuprincipal= int (input("Menu de análisis \n 1-Buscar sample \n 2-Analizar mediante hash \n 3-Subir archivo para análisis \n 4-Ver reporte del análisis \n 5-análisis con Viper subir archivo \n 6-Reporte de análisis con Viper\n 7-análisis con Cuckoo  \n 8-Salir \n")) 









