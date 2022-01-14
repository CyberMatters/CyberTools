#! python3
# Program written by Dany Giang aka CyberMatters

import requests
import json
import hashlib
import re
from bs4 import BeautifulSoup
import os
import magic
import argparse
import sys
import urllib.parse
import pandas as pd
import time

#*********************************************************** Virus Total functions **************************************
def virusTotalDomain(df,df_cpt,in_file,ioc, url, headers,payload):

    if (in_file == "y"): #operation result in file:

        try:
            res = requests.request("GET", url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            df.at[df_cpt,'error'] = error
        else:

            nice_json = re.sub('\'', '\"', res.text)
            data = json.loads(res.text)
            safe_ioc = re.sub("\.", "[.]", ioc)
            df.at[df_cpt,'domain'] = safe_ioc
            if ("error" in data) == False:

                try:
                    for key in data["data"]["attributes"]["categories"]:

                        df.at[df_cpt,'category'] = str(data["data"]["attributes"]["categories"][key])
                except:
                    df.at[df_cpt,'category'] = "Missing key in data"

                try:
                    df.at[df_cpt,'harmless'] = str(data["data"]["attributes"]["last_analysis_stats"]["harmless"])        
                except:
                    df.at[df_cpt,'harmless'] = "Missing key in data"

                try:
                    df.at[df_cpt,'malicious'] = str(data["data"]["attributes"]["last_analysis_stats"]["malicious"])                    
                except:
                    df.at[df_cpt,'malicious'] = "Missing key in data"

                try:
                    df.at[df_cpt,'suspicious'] = str(data["data"]["attributes"]["last_analysis_stats"]["suspicious"])                    
                except:
                    df.at[df_cpt,'suspicious'] = "Missing key in data"

                try:
                    df.at[df_cpt,'undetected'] = str(data["data"]["attributes"]["last_analysis_stats"]["undetected"])                    
                except:
                    df.at[df_cpt,'undetected'] = "Missing key in data"

                try:
                    for key in data["data"]["attributes"]["last_https_certificate"]["issuer"]:

                        df.at[df_cpt,'last_https_certificate_issuer'] = str(data["data"]["attributes"]["last_https_certificate"]["issuer"][key])
                except:
                    df.at[df_cpt,'last_https_certificate_issuer'] = "Missing key in data"

            else:

                df.at[df_cpt,'error'] = "There is an error"

    else: #operation result in terminal
    
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
                
def virusTotalHash(df,df_cpt,in_file,ioc, url, headers, payload):
      
    if (in_file == "y"): #operation result in file
    
        try:
            res = requests.request("GET", url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            df.at[df_cpt,'error'] = error

        else:
            data= json.loads(res.text)

            if data["data"] != []:

                df.at[df_cpt,'hash'] = ioc
                    
                try:
                    df.at[df_cpt,'file_type'] = str(data["data"][0]["attributes"]["type_description"])        
                except:
                    df.at[df_cpt,'file_type'] = "Missing key in data"
                
                try:
                    name_list = data["data"][0]["attributes"]["names"]
                    for name in name_list:
                        df.at[df_cpt,'file_name'] = df.at[df_cpt,'file_name'] + "~~" + name

                except:
                     df.at[df_cpt,'file_name'] ="Missing key in data"

                try:
                    key_list=["product", "verified", "description", "file version","signing date"]
                    i = 0
                    for key in data["data"][0]["attributes"]["signature_info"]:

                        if key in key_list : 
                            df.at[df_cpt,key] = str(data["data"][0]["attributes"]["signature_info"][key])

                except:
                    df.at[df_cpt,key] = "Missing key in data"

                try:
                    for key in data["data"][0]["attributes"]["last_analysis_stats"]:

                        try:
                            df.at[df_cpt,'harmless'] = str(data["data"][0]["attributes"]["last_analysis_stats"]["harmless"])        
                        except:
                            df.at[df_cpt,'harmless'] = "Missing key in data"

                        try:
                            df.at[df_cpt,'malicious'] = str(data["data"][0]["attributes"]["last_analysis_stats"]["malicious"])                    
                        except:
                            df.at[df_cpt,'malicious'] = "Missing key in data"

                        try:
                            df.at[df_cpt,'suspicious'] = str(data["data"][0]["attributes"]["last_analysis_stats"]["suspicious"])                    
                        except:
                            df.at[df_cpt,'suspicious'] = "Missing key in data"

                        try:
                            df.at[df_cpt,'undetected'] = str(data["data"][0]["attributes"]["last_analysis_stats"]["undetected"])                    
                        except:
                            df.at[df_cpt,'undetected'] = "Missing key in data"
                except:
                    df.at[df_cpt,'error'] = "Missing key in data"
            else:
                df.at[df_cpt,'error'] = "No matches found"
                
    else: #operation result in terminal
        print("******************************************")
        print("********** VIRUS TOTAL HASH MODULE ********")
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
                   
def virusTotalUrl(df,df_cpt,in_file,ioc, url, headers, payload):

    if (in_file == "y"): #operation result in file
        try :
            res = requests.request("POST", url, headers=headers, data=payload)
            res.raise_for_status()
          
        except Exception as error:
            df.at[df_cpt,'error'] = error

        else:
            data = json.loads(res.text)
            try:
                analysis_id = data["data"]["id"]

            except:
                    df.at[df_cpt,'error'] = "Missing key in data"

            else:
                url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

                try:
                    res = requests.request("GET", url, headers=headers)
                    res.raise_for_status()

                except Exception as error:
                    df.at[df_cpt,'error'] = error

                else:
                    nice_json = re.sub('\'', '\"', res.text)
                    data = json.loads(res.text)

                    safe_ioc = re.sub("\.", "[.]", ioc)
                    safe_ioc = re.sub("http", "hxxp", safe_ioc)
                    df.at[df_cpt,'url'] = safe_ioc                

                    try:
                        df.at[df_cpt,'harmless'] = str(data["data"]["attributes"]["stats"]["harmless"])        
                    except:
                        df.at[df_cpt,'harmless'] = "Missing key in data"

                    try:
                        df.at[df_cpt,'malicious'] = str(data["data"]["attributes"]["stats"]["malicious"])                    
                    except:
                        df.at[df_cpt,'malicious'] = "Missing key in data"

                    try:
                        df.at[df_cpt,'suspicious'] = str(data["data"]["attributes"]["stats"]["suspicious"])                    
                    except:
                        df.at[df_cpt,'suspicious'] = "Missing key in data"

                    try:
                        df.at[df_cpt,'undetected'] = str(data["data"]["attributes"]["stats"]["undetected"])                    
                    except:
                        df.at[df_cpt,'undetected'] = "Missing key in data"
  
    else:#operation result in terminal
        
        print("******************************************")
        print("********** VIRUS TOTAL URL MODULE ********")
        print("******************************************")
        try :
            res = requests.request("POST", url, headers=headers, data=payload)
            res.raise_for_status()
            
        except Exception as error:
            print(str(error))

        else:
            data = json.loads(res.text)
            try:
                analysis_id = data["data"]["id"]

            except:
                    print("Missing key in data")

            else:
                url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

                try:
                    res = requests.request("GET", url, headers=headers)
                    res.raise_for_status()

                except Exception as error:
                    print("request error")

                else:
                    nice_json = re.sub('\'', '\"', res.text)
                    data = json.loads(res.text)

                    print("\nResults for " + ioc)
                    print("\n\n*************** STATS ***********\n")                    

                    try:
                        for key in data["data"]["attributes"]["stats"]:

                            print("\n" + key + " : " + str(data["data"]["attributes"]["stats"][key]))

                    except:
                    
                        print("Missing key in data")

def virusTotalIp(df,df_cpt,in_file,ioc, url, headers,payload):

    if (in_file == "y"): #operation result in file
        try:
            res = requests.request("GET", url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            df.at[df_cpt,'error'] = error

        else:
            nice_json = re.sub('\'', '\"', res.text)
            data = json.loads(res.text)

            if ("error" in data) == False:

                safe_ioc = re.sub("\.", "[.]", ioc)
                df.at[df_cpt,'ip'] = safe_ioc

                try:
                    df.at[df_cpt,'harmless'] = str(data["data"]["attributes"]["last_analysis_stats"]["harmless"])        
                except:
                    df.at[df_cpt,'harmless'] = "Missing key in data"

                try:
                    df.at[df_cpt,'malicious'] = str(data["data"]["attributes"]["last_analysis_stats"]["malicious"])                    
                except:
                    df.at[df_cpt,'malicious'] = "Missing key in data"

                try:
                    df.at[df_cpt,'suspicious'] = str(data["data"]["attributes"]["last_analysis_stats"]["suspicious"])                    
                except:
                    df.at[df_cpt,'suspicious'] = "Missing key in data"

                try:
                    df.at[df_cpt,'undetected'] = str(data["data"]["attributes"]["last_analysis_stats"]["undetected"])                    
                except:
                    df.at[df_cpt,'undetected'] = "Missing key in data"

            else:
                    df.at[df_cpt,'error'] = "There is an error"

    else:#operation result in terminal
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

def setVTParam(vtApiKey) :

    print("******************************************")
    print("********** VIRUS TOTAL MODULE *********")
    print("******************************************")

    print ("Do you want the output to be saved in a CSV file ? y/n") 
    in_file = input()
            
    print ("Please enter MD5, SHA1, SHA256, ip address, domain name or URL\n")
    print()
    
    pattern_ipv4 = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_ipv6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
    pattern_domain = re.compile(r'^\.{0,1}(\w{1,63}\.\w+)$')
    pattern_url = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    pattern_md5 = re.compile(r'^[a-fA-F0-9]{32}$')
    pattern_sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
    pattern_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')

    ioc=input()
    scan_time = time.localtime(time.time())
    filename = "VirusTotal_" + str(scan_time.tm_year) + "_" + str(scan_time.tm_mon) + "_" + str(scan_time.tm_mday) + "_" + str(scan_time.tm_hour) + "-" + str(scan_time.tm_min) + "-" + str(scan_time.tm_sec) + ".csv"
    list=ioc.split(',')
    count=1

    # Create the dataframe that will contain the obfuscated commands and associated descriptions
    data = {'domain':[''],'ip':[''],'url':[''],'ip':[''],'hash':[''],'category':[''],'harmless':[''],'malicious':[''],'suspicious':[''],'undetected':[''],'last_https_certificate_issuer':[''],'file_type':[''],'file_name':[''],'product':[''],'verified':[''], 'description':[''], 'file version':[''],'signing date':[''],'error':['']}
    df = pd.DataFrame(data)
    df_cpt = -1

    for item in list :
        df_cpt += 1
        if (in_file != "y"):
            print("\n----------------------------\n")

        is_ipv4 = re.search(pattern_ipv4, item)
        is_ipv6 = re.search(pattern_ipv6, item)
        is_domain = re.search(pattern_domain, item)
        is_url = re.search(pattern_url, item)
        is_md5 = re.search(pattern_md5, item)
        is_sha1 = re.search(pattern_sha1, item)
        is_sha256 = re.search(pattern_sha256, item)

        headers = {
            'x-apikey': vtApiKey
        }

        if (is_md5 != None or is_sha1 != None or is_sha256 != None) :
            url = 'https://www.virustotal.com/api/v3/search?query='
      
            new_url = url + item
            payload = {}
                            
            virusTotalHash(df,df_cpt,in_file,item, new_url, headers, payload)

        elif (is_url != None) :
            url = 'https://www.virustotal.com/api/v3/urls'
            parsed_item = urllib.parse.quote(item, safe='')

            payload = "url=" + parsed_item
            print (payload)
            headers = {
                "Accept": "application/json",
                'x-apikey': vtApiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            }
    
            virusTotalUrl(df,df_cpt, in_file, item, url, headers, payload)
                      
        elif (is_domain != None) :
            url = 'https://www.virustotal.com/api/v3/domains/'    
            new_url = url + item
            payload={}
                
            virusTotalDomain(df,df_cpt,in_file,item, new_url, headers, payload)

        elif (is_ipv4 != None):
            url = "https://www.virustotal.com/api/v3/ip_addresses/"
            new_url = url + item
            payload={}
                
            virusTotalIp(df,df_cpt,in_file,item, new_url, headers, payload)

        elif (is_ipv6 != None):
            print("this is an IPv6 and unfortunately VirusTotal does not supports scanning this type of indicator.\nHowever, if your IPv6 address is IPv4-mapped IPv6 address (IPv6 that contains IPv4 like the following ::FFFF:129.144.52.38), then you can just scan the IPv4 part !!")
            
        else :
            print("Input error")            
            wait = input()
    
    if (in_file == "y"):
        df.to_csv(filename, index=False)
        
    print("operation finished successfully")
    wait = input()

#*********************************************************** PHISHTANK FUNCTION **************************************

def phishTank():

    os.system("cls")
    print("******************************************")
    print("************ PHISHTANK MODULE ************")
    print("******************************************")

    f=""
    print ("Do you want the results of your query in .\\results.txt ? y/n") 
    in_file = input()
    if (in_file == "y"):
        print ("Do you want to overwrite the content of results.txt ? y/n")
        
        overwrite = input()
        if (overwrite == "y"):
            f = open("results.txt","w")
        else:
            f = open("results.txt","a")
    
    print("\nEnter URL to check, separate them with comma")
    
    pattern_url = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urlToCheck = input()

    list = urlToCheck.split(',')
    
    if (in_file == "y"): #operation result in file
    
        for item in list:
            is_url = re.search(pattern_url, item)

            if is_url != None:
                url = "https://checkurl.phishtank.com/checkurl/index.php?url="
                new_url= url + item

                headers = {}
                payload = {}

                try:
                    res = requests.request("GET", new_url, headers=headers, data=payload)
                    res.raise_for_status()

                except Exception as error:
                    f.write(error)

                else:
                    soup = BeautifulSoup(res.text, 'xml')
                    
                    url = soup.select('url')

                    f.write("\nTHE URL TO SCAN IS ==> " + url[0].getText())

                    inDatabase = soup.select('in_database')
                    f.write("\nIN PHISHTANK DATABASE ==> " + inDatabase[0].getText()) 
                        
                    if (inDatabase[0].getText() == "true") :
                        try :
                            community = soup.select('verified')
                            f.write("\nVERIFIED BY THE COMMUNITY ==> " + community[0].getText()) 
                        except :
                            f.write("\nUNKNOWN IF VERIFIED")
                            
                        try :       
                            validity = soup.select('valid')
                            f.write("\nCONFIRMED PHISHING ==> " + validity[0].getText()) 
                        except :
                            f.write("\nUNKNOWN VALIDITY")
                            
                        try :
                            details = soup.select('phish_detail_page')
                            f.write("\nFIND DETAILS HERE ==> " + details[0].getText()) 
                        except :
                            f.write("\nUNKNOWN DETAILS")

            else :
                f.write("\nInvalid URL")
                
    else:#operation result in terminal

        for item in list:
            is_url = re.search(pattern_url, item)

            if is_url != None:
                url = "https://checkurl.phishtank.com/checkurl/index.php?url="
                new_url= url + item

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

    if (in_file == "y"):
        f.close()
        
    print("operation finished successfully")
    wait = input()

#*********************************************************** EmailRep FUNCTION **************************************

def emailRep() :

    os.system("cls")
    print("******************************************")
    print("************ EmailRep MODULE *************")
    print("******************************************")
 
    f=""
    print ("Do you want the results of your query in .\\results.txt ? y/n") 
    in_file = input()
    if (in_file == "y"):
        print ("Do you want to overwrite the content of results.txt ? y/n")
        
        overwrite = input()
        if (overwrite == "y"):
            f = open("results.txt","w")
        else:
            f = open("results.txt","a")
            
    print("\nInput email address to check")
    pattern_email = re.compile(r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$')

    addr = input()
    list = addr.split(',') 
    
    if (in_file == "y"): #operation result in file
    
        for item in list:
        
            is_email=re.search(pattern_email, item)

            if is_email != None:
                encodedEmail = re.sub("@", "%40", item)

                url = 'https://emailrep.io/query/'

                headers = {}
                payload = {}

                new_url = url + encodedEmail

                try :
                    res = requests.request("GET", new_url, headers=headers, data=payload)
                    res.raise_for_status()
                    
                except Exception as error:
                    f.write(error)    
                
                else:

                    data = json.loads(res.text)
                    f.write("\n************" + encodedEmail + "*************\n")

                    try :
                        f.write("\nEmail : " + str(data['email']))
                    except :
                        f.write("\nEmail : ???")
                        
                    try :
                        f.write("\nData breach : " + str(data["details"]['data_breach']))
                    except :
                        f.write("\ndata breach : ???")
                    
                    try :
                        f.write("\nEmail reputation : " + str(data['reputation']))
                    except :
                        f.write("\nEmail reputation : ???")
                        
                    try :
                        f.write("\nSuspicious : " + str(data['suspicious']))
                    except :
                        f.write("\nSuspicious : ???")
                        
                    try :
                        f.write("\nBlacklisted : " + str(data["details"]['blacklisted']))
                    except :
                        f.write("\nBlacklisted : ???")
                        
                    try :
                        f.write("\nMalicious activity : " + str(data["details"]['malicious_activity']))
                    except :
                        f.write("\nMalicious_activity : ???")
            else:
                f.write("Invalid email")
    
    else : #operation result in terminal

        for item in list:
        
            is_email=re.search(pattern_email, item)

            if is_email != None:
                encodedEmail = re.sub("@", "%40", item)

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

def shodanIP(shodanApiKey) :

    os.system("cls")
    print("******************************************")
    print("************ SHODAN IP MODULE ************")
    print("******************************************")
            
    print("\nEnter IP to check")
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')

    ip = input()

    is_ip = re.search(pattern_ip, ip)

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
    
def shodanDNSResolve(shodanApiKey) :

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
    
def shodanReverseDNS(shodanApiKey) :

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
    
def shodanMyHTTPHeaders(shodanApiKey) :

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
       
#*********************************************************** EXTRACT Indicators FUNCTION **************************************

def extractIndicators() :
    
    os.system("cls")
    print("******************************************")
    print("******* INDICATOR EXTRACTION MODULE ******")
    print("******************************************")

    ip_list = []
    domain_list = []
    url_list = []
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_domain = re.compile(r'\.{0,1}(\w{1,63}\.\w+)$')
    pattern_url = re.compile(r'https*:\/\/(?:\w+\.)+(?:\w+)(?:\/{0,1}\w+\.*)*')

    f= ""
    print ("Do you want the output to be saved in a CSV file ? y/n") 
    in_file = input()

    print("Enter files to analyze, separe with comma if many")
    filename = str.format(input())
    list = filename.split(",")
    
    if (in_file == "y"):#operation result in file
    
        for item in list:
            try:
                myFile = open(filename, 'r', encoding = 'utf-8', errors='ignore')

            except FileNotFoundError as error:
                f.write(error)

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
                    f.write("\nIP addresses were found!")
                    f.write(ip_list)
                    f.write()      
                else:
                    f.write("No IP addresses were found")

                if len(domain_list) != 0 :
                    f.write("\nDomains names were found!")
                    f.write(domain_list)
                    f.write()

                if len(url_list) != 0 :
                    f.write("\nURLs were found!")
                    f.write(url_list)
                    f.write()
                                
                else:
                    f.write("No URLs were found")
                    
    else:#operation result in terminal

        for item in list:
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

def threatCrowd_ip(f,in_file,ioc):

    if (in_file == "y"): #Operation result in file
        url = "http://www.threatcrowd.org/searchApi/v2/ip/report/"

        new_url = url + "?ip=" + ioc

        headers = {}
        payload = {}
        
        try:
            res =  requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            f.write(error)

        else:

            data= json.loads(res.text)

            f.write("\n\n*********** REPUTATION ********")
            try:
                if(data["votes"] == -1):
                    f.write("\n\n /!\\ MALICIOUS /!\\")
            
            except:
                f.write("Missing key in data")

            for key0 in data:
                f.write("\n********* " + key0 + " *********\n")
                try:
                    if isinstance(data[key0], list):
                        for value in data[key0]:
                            f.write(value)
                    
                    else:
                        f.write(data[key0])
                except:
                    ("Missing key in data")

    else: #Operation result in terminal
        
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

#*********************************************************** ThreatCrowd domain FUNCTION **************************************

def threatCrowd_domain(f,in_file,ioc):


    url = "http://www.threatcrowd.org/searchApi/v2/domain/report/"

    new_url = url + "?domain=" + ioc
    headers = {}
    payload = {}

    if (in_file == "y"): # Operation results in file
    
        try:
            res =  requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            f.write(error)

        else:
            data= json.loads(res.text)

            f.write("\n*********** REPUTATION ********")
            try:
                if(data["votes"] == -1):
                    f.write("\n /!\\ MALICIOUS /!\\")

                for key0 in data:
                    f.write("\n********* " + key0 + " *********\n")

                    if isinstance(data[key0], list):
                        for value in data[key0]:
                            f.write(value)
                    
                    else:
                        f.write(data[key0])
            except:
                f.write("Missing key in data")
                
    else: # Operation results in terminal
    
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

#*********************************************************** ThreatCrowd email FUNCTION **************************************

def threatCrowd_email(f,in_file,ioc):

    url = "http://www.threatcrowd.org/searchApi/v2/email/report/"

    new_url = url + "?email=" + ioc
    headers = {}
    payload = {}

    if (in_file == "y"): #Operation result in file
    
        try:
            res =  requests.request("GET", new_url, headers=headers, data=payload)
            res.raise_for_status()

        except Exception as error:
            f.write(error)

        else:
            data= json.loads(res.text)

            f.write("Results for " + ioc)
            if data["response_code"] == 1:

                try:
                    for key0 in data:
                        f.write("\n********* " + key0 + " *********\n")

                        if isinstance(data[key0], list):
                            for value in data[key0]:
                                f.write(value)
                        
                        else:
                            f.write(data[key0])
                except:
                    f.write("Missing key in data")
            else:
                f.write("Nothing was found for " + ioc)
                
    else: #Operation result in terminal
    
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

#*********************************************************** ThreatCrowd SET FUNCTION **************************************

def setThreatCrowdParam() :

    print("******************************************")
    print("********** THREAT CROWD MODULE *********")
    print("******************************************")

    f=""
    print ("Do you want the results of your query in .\\results.txt ? y/n") 
    in_file = input()
    if (in_file == "y"):
        print ("Do you want to overwrite the content of results.txt ? y/n")
        
        overwrite = input()
        if (overwrite == "y"):
            f = open("results.txt","w")
        else:
            f = open("results.txt","a")
            
    print ("Please enter domain, IP address or email address\n")
    
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{0,5}){0,1}')
    pattern_domain = re.compile(r'^\.{0,1}(\w{1,63}\.\w+)$')
    pattern_email = re.compile(r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$')

    ioc = input()
    list = ioc.split(",")

    count = 1
    
    for item in list:
        is_ip = re.search(pattern_ip, item)
        is_domain = re.search(pattern_domain, item)
        is_email = re.search(pattern_email, item)

        if (is_ip != None) :

            if (count == 1):
                print("******************************************")
                print("********** THREAT CROWD IP MODULE ********")
                print("******************************************")
                count +=1
            
            threatCrowd_ip(f,in_file,item)
                

        elif (is_email != None) :

            if (count == 1):
                print("******************************************")
                print("******** THREAT CROWD EMAIL MODULE *******")
                print("******************************************")
                count +=1
                
            threatCrowd_email(f,in_file,item)

        elif (is_domain != None) :

            if (count == 1):
                print("******************************************")
                print("******** THREAT CROWD DOMAIN MODULE *******")
                print("******************************************")
                count +=1
                
            threatCrowd_domain(f,in_file,item)

        else :
            if (in_file == "y"):
                f.write("input error")
            else:
                print("Input error")            
            return
    
    if (in_file == "y"):
        f.close()
        
    print("operation finished successfully")
    wait = input()
    

#*********************************************************** MAIN()**************************************

def main(argv):

    #**************** API keys **************

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="-i is followed by the path of the json file which contains your api key", required=True)
    args = parser.parse_args()

    filePath = args.input

    try:
        with open(filePath, "r") as key_file:
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
        print("05 ==> Hash a text")
        print("06 ==> Hash a file")
        print("07 ==> SHODAN IP Search")
        print("08 ==> SHODAN DNS resolve")
        print("09 ==> SHODAN Reverse DNS")
        print("10 ==> SHODAN show my HTTP headers")
        print("11 ==> Sanitize URL")
        print("12 ==> Desanitize URL")
        print("13 ==> Extract IP addresses, domain names and URLs from txt file")
        print("14 ==> Get file magic number")
        
        print("\nType \'exit\' to exit the program :)")

        print()

        MenuDecision = input()
            
        if (MenuDecision == '01' or MenuDecision == '1') :    
            setVTParam(vtApiKey)

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

            shodanIP(shodanApiKey) 
            
        elif (MenuDecision == '08' or MenuDecision == '8') :

            shodanDNSResolve(shodanApiKey)
            
        elif (MenuDecision == '09' or MenuDecision == '9') :

            shodanReverseDNS(shodanApiKey)

        elif (MenuDecision == '10') :

            shodanMyHTTPHeaders(shodanApiKey)
            
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

