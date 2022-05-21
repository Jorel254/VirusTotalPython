from cgitb import text
from contextlib import nullcontext
import json
from multiprocessing import Pipe
import os
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
file_path=""
CuerrentSystem = platform.system()
menuprincipal= int (input("Menu de analisis \n 1- Buscar sample \n 2-Analizar mediante hash \n 3-Subir archivo para analisis \n 4-Ver reporte del analisis \n 5-Analisis con Viper subir archivo \n 6-Reporte de analisis con Viper  \n 7-Salir \n"))  
while menuprincipal!=7:
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
        print("Iniciando analisis")
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
        print("El hash del archivo es: " + HashFile)
        api_url = 'https://www.virustotal.com/api/v3/files/'+ HashFile
        headers = {'x-apikey' : ""}#Insert your API key here !!!!!
        response = requests.get(api_url, headers=headers)
        if (response.status_code != 200):
            print("Not found sample")
        else:
            response_jason= json.loads(response.text)
            documentText = response_jason['data']
            # print(documentText)
            print("Selecciona un directorio para guardar el reporte")
            root = Tk()
            root.withdraw()
            root.update()
            directory= askdirectory();
            root.destroy()
            if(directory != ""):
                # file = open(directory+"/"+ HashFile+".json", "w") 
                # file.write(str(response_jason['data']))
                # file.close()
                with open(directory+"/"+ HashFile+".json", 'w') as json_file:
                    json.dump(response_jason['data'], json_file)
            else:
                print("No selecciono ningun directorio")
            time.sleep(3)
    elif menuprincipal ==3:
        #Subir archivo para analisis
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
        input()  
    elif menuprincipal == 4:
        #Ver reporte del analisis
        print("Inserte el ID del escaneo del cual quiero obtener informacion")   
        ID=input()
        url = "https://www.virustotal.com/api/v3/files/" +  ID
        headers = {"Accept": "application/json"}
        response = requests.request("GET", url, headers=headers)
        if (response.status_code != 200):
            print("Not found sample")
        else:
            response_jason= json.loads(response.text)
            documentText = response_jason['data']
            with open(directory + "/"+ ID +".json", 'w') as json_file:
                json.dump(response_jason['data'], json_file)
            print(documentText)
    elif menuprincipal == 5:
        #Analisis con Viper subir archivo
        print("Analisis con Viper") 
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
        #Reporte de analisis con Viper
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
    else:
        print("Escriba una opcion correcta")
    os.system ("clear")    
    menuprincipal= int (input("Menu de analisis \n 1- Buscar sample \n 2-Analizar mediante hash \n 3-Subir archivo para analisis \n 4-Ver reporte del analisis \n 5-Analisis con Viper subir archivo \n 6-Reporte de analisis con Viper \n 7-Salir \n")) 









