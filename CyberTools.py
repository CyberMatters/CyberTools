#! python3
# Program written by Dany Giang aka CyberMatters

import requests
import json
import hashlib
import re
from bs4 import BeautifulSoup
import os
import magic
import sys

#*********************************************************** Virus Total functions **************************************
def virusTotalDomain(ioc, url, headers,payload):

    os.system("cls")
    print("******************************************")
    print("******** VIRUS TOTAL DOMAIN MODULE *******")
    print("******************************************")

    try:
        res = requests.request("GET", url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:

        nice_json = re.sub('\'', '\"', res.text)
        data = json.loads(res.text)
        print("Results for " + ioc)
        if ("error" in data) == False:

            print("\n*************** CATEGORIES ***********\n")

            try:
                for key in data["data"]["attributes"]["categories"]:

                    print(key + " : " + str(data["data"]["attributes"]["categories"][key]))

            except:
                print("Missing key in data")

            print("\n*************** LAST ANALYSIS STATS ***********\n")

            try:               
                for key in data["data"]["attributes"]["last_analysis_stats"]:

                    print(key + " : " + str(data["data"]["attributes"]["last_analysis_stats"][key]))

            except:
                print("Missing key in data")


            print("\n*************** LAST HTTPS CERTIFICATE ISSUER ***********\n")
            try:
                for key in data["data"]["attributes"]["last_https_certificate"]["issuer"]:

                    print(key + " : " + str(data["data"]["attributes"]["last_https_certificate"]["issuer"][key]))

            except:
                print("Missing key in data")

        else:
            print("\nThere is an error :\n")
            print(data["error"]["message"])

    wait = input()

def virusTotalHash(ioc, url, headers, payload):

    os.system("cls")
    print("******************************************")
    print("******** VIRUS TOTAL HASH MODULE *******")
    print("******************************************")

    try:
        res = requests.request("GET", url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:
        data= json.loads(res.text)

        if data["data"] != []:

            print("\nResults for " + ioc)

            print("\n*************** FILE TYPE ***********\n")
            try:
                print("type_description" + " : " + str(data["data"][0]["attributes"]["type_description"]))

            except:
                print("Missing key in data")

            print("\n*************** FILE NAMES ***********\n")
            try:
                name_list = data["data"][0]["attributes"]["names"]
                for name in name_list:
                    print(name)

            except:
                print("Missing key in data")

            print("\n*************** SIGNATURE ***********\n") 
            try:
                key_list=["product", "verified", "description", "file version","signing date"]
                i = 0
                for key in data["data"][0]["attributes"]["signature_info"]:

                    if key in key_list and key != "x509":
                        print(key + " : " + str(data["data"][0]["attributes"]["signature_info"][key]))
                    elif key == "x509":
                        for item in data["data"][0]["attributes"]["signature_info"]["x509"]:
                            print()
                            for key2 in item:
                                print(key2 + " : " + str(data["data"][0]["attributes"]["signature_info"]["x509"][i][key2]))
                            i = i + 1

            except:
                print("Missing key in data")

            print("\n*************** LAST ANALYSYS STATS ***********\n") 
            try:
                for key in data["data"][0]["attributes"]["last_analysis_stats"]:

                    print(key + " : " + str(data["data"][0]["attributes"]["last_analysis_stats"][key]))

            except:
                print("Missing key in data")
        else:
            print("No matches found")

    wait=input() 
    
def virusTotalUrl(ioc, url, headers, payload, files):

    os.system("cls")
    print("******************************************")
    print("********** VIRUS TOTAL URL MODULE ********")
    print("******************************************")

    try :
        res = requests.request("POST", url, headers=headers, data=payload, files=files)
        res.raise_for_status()
      
    except Exception as error:
        print(error)

    else:
        data = json.loads(res.text)  

        try:
            analysis_id = data["data"]["id"]

        except:
            print("Missing key in data")

        else:
            url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id
            headers = {'x-apikey': vtApiKey}
            payload={}

            try:
                res = requests.request("GET", url, headers=headers, data=payload)
                res.raise_for_status()

            except Exception as error:
                print(error)

            else:
                nice_json = re.sub('\'', '\"', res.text)
                data = json.loads(res.text)

                print("\nResults for " + ioc)
                print("\n*************** STATS ***********\n")

                try:
                    for key in data["data"]["attributes"]["stats"]:

                        print(key + " : " + str(data["data"]["attributes"]["stats"][key]))

                except:
                    print("Missing key in data")

    wait=input() 

def virusTotalIp(ioc, url, headers,payload):

    os.system("cls")
    print("******************************************")
    print("********** VIRUS TOTAL IP MODULE *********")
    print("******************************************")

    try:
        res = requests.request("GET", url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:
        nice_json = re.sub('\'', '\"', res.text)
        data = json.loads(res.text)

        if ("error" in data) == False:

            print("\nResults for " + ioc)
            print("\n*************** LAST ANALYSIS STATS ***********\n")

            try:
                for key in data["data"]["attributes"]["last_analysis_stats"]:

                    print(key + " : " + str(data["data"]["attributes"]["last_analysis_stats"][key]))

            except:
                print("Missing key in data")

        else:
            print("\nThere is an error :\n")
            print(data["error"]["message"])

    wait = input()

def setVTParam() :

    os.system("cls")
    print("******************************************")
    print("********** VIRUS TOTAL MODULE *********")
    print("******************************************")

    print ("Please enter MD5, SHA1, SHA256, ip address, domain name or URL\n")
    print()
    
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_domain = re.compile(r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b')
    pattern_url = re.compile(r'(?:http|https|ftp|sftp){0,1}:\/\/(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b(?:[a-zA-Z0-9@:%._\+~#?&\/=-]+)*')
    pattern_md5 = re.compile(r'^[a-fA-F0-9]{32}$')
    pattern_sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
    pattern_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')

    ioc=input()

    is_ip = re.fullmatch(pattern_ip, ioc)
    is_domain = re.fullmatch(pattern_domain, ioc)
    is_url = re.fullmatch(pattern_url, ioc)
    is_md5 = re.fullmatch(pattern_md5, ioc)
    is_sha1 = re.fullmatch(pattern_sha1, ioc)
    is_sha256 = re.fullmatch(pattern_sha256, ioc)

    headers = {
        'x-apikey': vtApiKey
    }

    if (is_md5 != None or is_sha1 != None or is_sha256 != None) :
        url = 'https://www.virustotal.com/api/v3/search?query='
  
        new_url = url + ioc
        payload = {}

        virusTotalHash(ioc, new_url, headers, payload)
        
    elif (is_url != None) :
        url = 'https://www.virustotal.com/api/v3/urls'
    
        payload={'url': ioc}
        files=[]

        virusTotalUrl(ioc, url, headers, payload,files)
    
    elif (is_domain != None) :
        url = 'https://www.virustotal.com/api/v3/domains/'
 
        new_url = url + ioc
        payload={}
        virusTotalDomain(ioc, new_url, headers, payload)

    elif (is_ip != None):
        url = "https://www.virustotal.com/api/v3/ip_addresses/"

        new_url = url + ioc
        payload={}
        virusTotalIp(ioc, new_url, headers, payload)

    else :
        print("Input error")
        wait = input()
        return

#*********************************************************** PHISHTANK FUNCTION **************************************

def phishTank():

    os.system("cls")
    print("******************************************")
    print("************ PHISHTANK MODULE ************")
    print("******************************************")

    print("\nEnter URL to check")
    
    pattern_url = re.compile(r'(?:http|https|ftp|sftp){0,1}:\/\/(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b(?:[a-zA-Z0-9@:%._\+~#?&\/=-]+)*')
    urlToCheck = input()

    is_url = re.fullmatch(pattern_url, urlToCheck)

    if is_url != None:
        url = "https://checkurl.phishtank.com/checkurl/index.php?url="
        new_url= url + urlToCheck

        headers = {}
        payload = {}

        try:
            res = requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            print(error)

        else:
            soup = BeautifulSoup(res.text, 'xml')
            
            url = soup.select('url')
            print()
            print("THE URL TO SCAN IS ==> " + url[0].getText())

            inDatabase = soup.select('in_database')
            print("IN PHISHTANK DATABASE ==> " + inDatabase[0].getText()) 
                
            if (inDatabase[0].getText() == "true") :
                try :
                    community = soup.select('verified')
                    print("VERIFIED BY THE COMMUNITY ==> " + community[0].getText()) 
                except :
                    print("UNKNOWN IF VERIFIED")
                    
                try :       
                    validity = soup.select('valid')
                    print("CONFIRMED PHISHING ==> " + validity[0].getText()) 
                except :
                    print("UNKNOWN VALIDITY")
                    
                try :
                    details = soup.select('phish_detail_page')
                    print("FIND DETAILS HERE ==> " + details[0].getText()) 
                except :
                    print("UNKNOWN DETAILS")

    else :
        print("Invalid URL")

    wait=input() 

#*********************************************************** EmailRep FUNCTION **************************************

def emailRep() :

    os.system("cls")
    print("******************************************")
    print("************ EmailRep MODULE *************")
    print("******************************************")
  
    print("\nInput email address to check")
    pattern_email = re.compile(r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$')

    addr = input()

    is_email=re.fullmatch(pattern_email, addr)

    if is_email != None:
        encodedEmail = re.sub("@", "%40", addr)

        url = 'https://emailrep.io/query/'

        headers = {}
        payload = {}

        new_url = url + encodedEmail

        try :
            res = requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()
            
        except Exception as error:
            print(error)    
        
        else:

            data = json.loads(res.text)
            print("\n************" + encodedEmail + "*************\n")

            try :
                print("\nEmail : " + str(data['email']))
            except :
                print("\nEmail : ???")
                
            try :
                print("\nData breach : " + str(data["details"]['data_breach']))
            except :
                print("\ndata breach : ???")
            
            try :
                print("\nEmail reputation : " + str(data['reputation']))
            except :
                print("\nEmail reputation : ???")
                
            try :
                print("\nSuspicious : " + str(data['suspicious']))
            except :
                print("\nSuspicious : ???")
                
            try :
                print("\nBlacklisted : " + str(data["details"]['blacklisted']))
            except :
                print("\nBlacklisted : ???")
                
            try :
                print("\nMalicious activity : " + str(data["details"]['malicious_activity']))
            except :
                print("\nMalicious_activity : ???")
    else:
        print("Invalid email")

    wait=input() 
    
#*********************************************************** HASHTEXT FUNCTION **************************************

def hashText() :

    os.system("cls")    
    print("******************************************")
    print("************* HASH TEXT MODULE ***********")
    print("******************************************")

    print("input text to hash")
    text = input()
    
    hashMd5 = hashlib.md5()
    hashMd5.update(bytes(text,'utf-8'))   
    print("md5 hash is : " + hashMd5.hexdigest())
    
    hashsha1 = hashlib.sha1()
    hashsha1.update(bytes(text,'utf-8'))   
    print("SHA1 hash is : " + hashsha1.hexdigest())
    
    hashsha256 = hashlib.sha256()
    hashsha256.update(bytes(text,'utf-8'))   
    print("SHA256 hash is : " + hashsha256.hexdigest())

    wait=input() 
#*********************************************************** HASHFILE FUNCTION **************************************

def hashFile() :

    os.system("cls")
    print("******************************************")
    print("************* HASH FILE MODULE ***********")
    print("******************************************")

    print("Enter path of file, separate by comma if multiple files")
    filename = str.format(input())
    fileList = filename.split(',')
    
    for x in fileList :
        hashMd5 = hashlib.md5()
        hashsha1 = hashlib.sha1()
        hashsha256 = hashlib.sha256()
        # open file for reading in binary mode
        try:
            with open(x,'rb') as file:

                # loop until the end of the file
                chunk = 0
                while chunk != b'':
                    # read only 1024 bytes at a time
                    chunk = file.read(1024)
                    hashMd5.update(chunk)
                    hashsha1.update(chunk)
                    hashsha256.update(chunk)

        except FileNotFoundError as error:
            print(error)

        else:
            print("\n************" + x + "*************")
            print("md5 hash is : " + hashMd5.hexdigest())
            print("SHA1 hash is : " + hashsha1.hexdigest())
            print("SHA256 hash is : " + hashsha256.hexdigest())

    wait=input() 
    
#*********************************************************** SHODAN FUNCTIONs **************************************

def shodanIP() :

    os.system("cls")
    print("******************************************")
    print("************ SHODAN IP MODULE ************")
    print("******************************************")
            
    print("\nEnter IP to check")
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')

    ip = input()

    is_ip = re.fullmatch(pattern_ip, ip)

    if is_ip != None:
        url = 'https://api.shodan.io/shodan/host/'

        new_url = url + ip + "?key=" + shodanApiKey + "&minify=true"

        headers = {}
        payload = {}

        try:
            res = requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()
            
        except Exception as error:
            print(error)

        else:
            data = json.loads(res.text)

            if ("error" in data) == False:
            
                print("\nThe result from SHODAN are shown below : \n")
                
                try :
                    print("\nORG : " + data['org'])

                except :
                    print("No org detected\n")
                
                try :
                    print("\nISP : " + data['org'])

                except :
                    print("No isp detected\n")
                    
                try :
                    print("\nDOMAIN : " + data['domains'][0])

                except :
                    print("No domain detected\n")
            
                try :
                    print("\nHOSTNAME : " + data['hostnames'][0])

                except :
                    print("No hostnames detected\n")
                        
                try :
                    print("\nOS : " + data['os'])

                except :
                    print("No OS detected\n")
                    
                try :
                    print("\nOPEN PORTS: " + str(data['ports']))

                except :
                    print("No ports detected\n")

            else:
                print("\nInvalid IP")
    else:
        print("\nInvalid IP")

    wait=input() 
    
def shodanDNSResolve() :

    os.system("cls")
    print("******************************************")
    print("******** SHODAN DNS RESOLVE MODULE *******")
    print("******************************************")
            
    print("\nEnter hostname to resolve")        
    hostname = input()
    url = 'https://api.shodan.io/dns/resolve'

    new_url = url + "?key=" + shodanApiKey + "&hostnames=" + hostname

    headers = {}
    payload = {}

    try:
        res = requests.request("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()
        
    except Exception as error:
        print(error)

    else:
        data = json.loads(res.text)
        try:
            print(hostname + " : " + str(data[hostname]))
        except:
            print("Missing key in data")

    wait=input() 
    
def shodanReverseDNS() :

    os.system("cls")
    print("******************************************")
    print("******** SHODAN Reverse DNS MODULE *******")
    print("******************************************")
            
    print("\nEnter IPs to resolve")        
    ip = input()
    url = 'https://api.shodan.io/dns/reverse'
    params={'key' : shodanApiKey, 'ips' : ip}
    
    new_url = url + "?key=" + shodanApiKey + "&ips=" + ip

    headers = {}
    payload = {}

    try:
        res = requests.request("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()
    
    except Exception as error:
        print(error)

    else:
        data = json.loads(res.text)
        try: 
            print(str(ip) + " : " + str(data[ip]))
        except:
            print("Missing key in data")

    wait=input() 
    
def shodanMyHTTPHeaders() :

    os.system("cls")
    print("******************************************")
    print("****** SHODAN MY HTTP HEADERS MODULE *****")
    print("******************************************")
    print()
            
    url = 'https://api.shodan.io/tools/httpheaders'
    params={'key' : shodanApiKey}
    
    new_url = url + "?key=" + shodanApiKey
    headers = {}
    payload = {}

    try:
        res = requests.requests("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:
        headers = (res.text).split(',')
        
        for item in headers:
            print(item)

    wait=input() 
    
#*********************************************************** SANITIZE FUNCTION **************************************

def sanitize() :
    
    os.system("cls")

    print("******************************************")
    print("************ SANITIZE MODULE ***********")
    print("******************************************")

    print("\ninput URLs to sanitize, separated by comma")
    dangerousUrl = input()
    
    list=dangerousUrl.split(',')
    
    print()
    for item in list :
        safeUrl = re.sub("\.", "[.]", item)
        safeUrl = re.sub("http", "hxxp", safeUrl)
        print (safeUrl)

    wait=input() 

#*********************************************************** DESANITIZE FUNCTION **************************************

def deSanitize():

    os.system("cls")

    print("******************************************")
    print("************ DESANITIZE MODULE ***********")
    print("******************************************")

    print("\ninput URLs to desanitize, separated by comma")
    sanitizedUrl = input()
    
    list=sanitizedUrl.split(',')
    
    print()
    for item in list :
        dangerousUrl = re.sub("\[", "", item)
        dangerousUrl = re.sub("\]", "", dangerousUrl)
        dangerousUrl = re.sub("hxxp", "http", dangerousUrl)
        
        print (dangerousUrl)

    wait=input() 
       
#***********************************************************  EXTRACT Indicators FUNCTION **************************************

def extractIndicators() :
    
    os.system("cls")
    print("******************************************")
    print("******* INDICATOR EXTRACTION MODULE ******")
    print("******************************************")

    ip_list = []
    domain_list = []
    url_list = []
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_domain = re.compile(r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b')
    pattern_url = re.compile(r'(?:http|https|ftp|sftp){0,1}:\/\/(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b(?:[a-zA-Z0-9@:%._\+~#?&\/=-]+)*')
    
    print("Enter txt file to analyze")
    filename = str.format(input())
    try:
        myFile = open(filename, 'r', encoding = 'utf-8', errors='ignore')

    except FileNotFoundError as error:
        print(error)

    else:
        Lines = myFile.readlines()

        for line in Lines :
        
            temp_ip_list = pattern_ip.findall(line)
            temp_domain_list = pattern_domain.findall(line)
            temp_url_list = pattern_url.findall(line)
            
            if len(temp_ip_list) != 0 :

                for ip in temp_ip_list:          
                    ip_list.append(ip)

            if len(temp_domain_list) != 0 :

                for domain in temp_domain_list:          
                    domain_list.append(domain)

            if len(temp_url_list) != 0 :

                for url in temp_url_list:          
                    url_list.append(url)

        if len(ip_list) != 0 :
            print("\nIP addresses were found!")
            print(ip_list)
            print()      
        else:
            print("No IP addresses were found")

        if len(domain_list) != 0 :
            print("\nDomains names were found!")
            print(domain_list)
            print()

        if len(url_list) != 0 :
            print("\nURLs were found!")
            print(url_list)
            print()
                        
        else:
            print("No URLs were found")
        
    wait=input()

#*********************************************************** Magic Number FUNCTION **************************************

def magicNumber() :

    os.system("cls")
    print("******************************************")
    print("*********** MAGIC NUMBER MODULE **********")
    print("******************************************")

    print("input files to check, separated by comma")
    my_input = input()
    fileList = my_input.split(',')
    
    for file in fileList:
        print("The type of file of " + file + " is :")
        try:
            print(magic.from_file(file,mime=True))
        except FileNotFoundError as error:
            print(error)
        
    wait = input()

#*********************************************************** ThreatCrowd ip FUNCTION **************************************

def threatCrowd_ip(ioc):

    os.system("cls")
    print("******************************************")
    print("********** THREAT CROWD IP MODULE ********")
    print("******************************************")

    url = "http://www.threatcrowd.org/searchApi/v2/ip/report/"

    new_url = url + "?ip=" + ioc

    headers = {}
    payload = {}

    try:
        res =  requests.request("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:

        data= json.loads(res.text)

        print("\n*********** REPUTATION ********")
        try:
            if(data["votes"] == -1):
                print("\n /!\\ MALICIOUS /!\\")
        
        except:
            print("Missing key in data")

        for key0 in data:
            print("\n********* " + key0 + " *********\n")
            try:
                if isinstance(data[key0], list):
                    for value in data[key0]:
                        print(value)
                
                else:
                    print(data[key0])
            except:
                ("Missing key in data")

    wait = input()

#*********************************************************** ThreatCrowd domain FUNCTION **************************************

def threatCrowd_domain(ioc):

    os.system("cls")
    print("******************************************")
    print("******** THREAT CROWD DOMAIN MODULE ******")
    print("******************************************")

    url = "http://www.threatcrowd.org/searchApi/v2/domain/report/"

    new_url = url + "?domain=" + ioc
    headers = {}
    payload = {}

    try:
        res =  requests.request("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:
        data= json.loads(res.text)

        print("\n*********** REPUTATION ********")
        try:
            if(data["votes"] == -1):
                print("\n /!\\ MALICIOUS /!\\")

            for key0 in data:
                print("\n********* " + key0 + " *********\n")

                if isinstance(data[key0], list):
                    for value in data[key0]:
                        print(value)
                
                else:
                    print(data[key0])
        except:
            print("Missing key in data")

    wait = input()

#*********************************************************** ThreatCrowd email FUNCTION **************************************

def threatCrowd_email(ioc):

    os.system("cls")
    print("******************************************")
    print("******** THREAT CROWD EMAIL MODULE *******")
    print("******************************************")

    url = "http://www.threatcrowd.org/searchApi/v2/email/report/"

    new_url = url + "?email=" + ioc
    headers = {}
    payload = {}

    try:
        res =  requests.request("GET", new_url, headers=headers, data=payload)
        res.raise_for_status()

    except Exception as error:
        print(error)

    else:
        data= json.loads(res.text)

        print("Results for " + ioc)
        if data["response_code"] == 1:

            try:
                for key0 in data:
                    print("\n********* " + key0 + " *********\n")

                    if isinstance(data[key0], list):
                        for value in data[key0]:
                            print(value)
                    
                    else:
                        print(data[key0])
            except:
                print("Missing key in data")
        else:
            print("Nothing was found for " + ioc)

    wait = input()

#*********************************************************** ThreatCrowd SET FUNCTION **************************************

def setThreatCrowdParam() :

    print("******************************************")
    print("********** THREAT CROWD MODULE *********")
    print("******************************************")

    print ("Please enter domain, IP address or email address\n")
    
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_domain = re.compile(r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b')
    pattern_email = re.compile(r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$')

    ioc=input()

    is_ip = re.fullmatch(pattern_ip, ioc)
    is_domain = re.fullmatch(pattern_domain, ioc)
    is_email = re.fullmatch(pattern_email, ioc)

    headers = {
        'x-apikey': vtApiKey
    }

    if (is_ip != None) :
        
        threatCrowd_ip(ioc)

    elif (is_email != None) :
        
        threatCrowd_email(ioc)

    elif (is_domain != None) :
        
        threatCrowd_domain(ioc)

    else:
        print("Input error !")
        wait = input()
        return

#*********************************************************** MAIN()**************************************

def main(argv):
    
    #*********** API keys **********
    try:
        with open("api_keys.json", "r") as key_file:
            data = json.load(key_file)
            vtApiKey = data["vtApiKey"]
            shodanApiKey = data["shodanApiKey"]

    except FileNotFoundError as error:
        print(error)

    #**************** CyberTools Menu **************
    while (1 == 1): 
        os.system("cls")
        print("******************************************")
        print("**************** CyberTools **************")
        print("****** by Dany Giang aka CyberMatters ****")
        print("******************************************")

        print("\nChoose the action to perform by entering the corresponding number :\n")
        print("01 ==> VirusTotal module - Scan hashes, URLs, domains, IP addresses")
        print("02 ==> ThreatCrowd module - Scan domains, IP addresses, email addresses")
        print("03 ==> PhishTank module - check phishing URL")
        print("04 ==> EmailRep module - Check email reputation")
        print("05 ==> Compute the hash value of a text")
        print("06 ==> Compute the hash value of a file")
        print("07 ==> SHODAN IP Search")
        print("08 ==> SHODAN DNS resolve")
        print("09 ==> SHODAN Reverse DNS")
        print("10 ==> SHODAN show my HTTP headers")
        print("11 ==> Sanitize URL")
        print("12 ==> Desanitize URL")
        print("13 ==> Extract IP addresses, domain names and URLs from file")
        print("14 ==> Get file magic number")

        print("\nType \'exit\' to exit the program :)")

        print()

        MenuDecision = input()

        if (MenuDecision == '01' or MenuDecision == '1') :    
            setVTParam()

        elif (MenuDecision == '02' or MenuDecision == '2'):

            setThreatCrowdParam()

        elif (MenuDecision == '03' or MenuDecision == '3'):

            phishTank()

        elif (MenuDecision == '04' or MenuDecision == '4') :

            emailRep()  

        elif (MenuDecision == '05' or MenuDecision == '5') :

            hashText()  

        elif (MenuDecision == '06' or MenuDecision == '6') :

            hashFile() 

        elif (MenuDecision == '07' or MenuDecision == '7') :

            shodanIP() 

        elif (MenuDecision == '08' or MenuDecision == '8') :

            shodanDNSResolve()

        elif (MenuDecision == '09' or MenuDecision == '9') :

            shodanReverseDNS()

        elif (MenuDecision == '10') :

            shodanMyHTTPHeaders()

        elif (MenuDecision == '11') :

            sanitize()

        elif (MenuDecision == '12') :

            deSanitize()

        elif (MenuDecision == '13'):

            extractIndicators()   

        elif (MenuDecision == '14'):

            magicNumber()   

        elif (MenuDecision == 'exit') :

            exit()

        else :
            print("Incorrect input")

if __name__=="__main__":
    main(sys.argv[1:])
