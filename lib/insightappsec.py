import requests
import time
import math
import pytz
import sys
import pandas as pd
import openpyxl
import json
import os
from datetime import datetime, timedelta
from dateutil.parser import parse as parseDate
from bs4 import BeautifulSoup
from .valid_filename import slugify

import email
from io import StringIO

class InsightAppSec:
    class Scan:
        def __init__(self, scanId, status, submitTime, completionTime):
            self.id = scanId
            self.status = status
            self.submit_time = submitTime
            self.completion_time = completionTime
        
    class Vulnerability:
        def __init__(self, vulnerability, module_details):
            self.root_cause_url = vulnerability["root_cause"]["url"] if vulnerability.get("root_cause") else ""
            self.method = vulnerability["root_cause"]["method"] if vulnerability.get("root_cause") else ""
            self.parameter = vulnerability["root_cause"]["parameter"] if vulnerability.get("root_cause",{}).get("parameter") else ""
            self.severity = vulnerability.get("severity","")
            self.status = vulnerability.get("status", "")
            self.id = vulnerability.get("id", "")
            self.score = vulnerability.get("vulnerability_score", "")
            self.insight_url = vulnerability.get("insight_ui_url", "")
            self.module_name = module_details.get("module_name", "")
            self.module_description = module_details.get("module_description", "")
            self.vector = vulnerability.get("vector_string", "")
            self.attack_id = module_details.get("attack_id", "")
            self.attack_value = vulnerability["variances"][0].get("attack_value", "")
            self.attack_description = module_details.get("attack_documentation_description", "")
            self.recommendation = module_details.get("attack_documentation_recommendation", "")

    def __init__(self, api_key, region='us'):
        self.__api_key = api_key
        self.__headers = {
            'X-Api-Key': self.__api_key
        }
        self.region = region
        self.endpoints = {
            "validate": f"https://{self.region}.api.insight.rapid7.com/validate",
            "apps": f"https://{self.region}.api.insight.rapid7.com/ias/v1/apps",
            "scans": f"https://{self.region}.api.insight.rapid7.com:443/ias/v1/scans",
            "vulnerabilities": f"https://{self.region}.api.insight.rapid7.com/ias/v1/vulnerabilities",
            "module": f"https://{self.region}.api.insight.rapid7.com/ias/v1/modules",
        }
        """
        Structure of __modules register
            {
                "module_id": {
                    "name": "",
                    "id": "",
                    "description": "",
                    "attacks": {
                        "attack_id": {
	                        "type": "",
	                        "class": "",
	                        "attack_description": "",
	                        "description": "",
	                        "recommendation": ""
	                    }
                    }
                }
            }
        """
        self.__modules = {}


    def get(self, url, headers, params={}, verify=True):
        pingcon = 0
        while True:
            try:
                response = requests.request("GET", url, headers=headers, params=params, verify=verify)
                if response.headers.get("RateLimit-Remaining","") == '0': # and response.status_code == 403:
                    wait_seconds = math.ceil(int(response.headers["RateLimit-Reset"]) - time.time())
                    if wait_seconds > 0:
                        IST = pytz.timezone('Asia/Kolkata')
                        print(f"[Resumes at {datetime.now() + timedelta(seconds=wait_seconds)}] : Rate Limit Exceded: waiting for {wait_seconds} seconds, IND({(datetime.now(IST) + timedelta(seconds=wait_seconds)).strftime('%H:%M:%S')})")
                        time.sleep(wait_seconds)
                        response = requests.request("GET", url, headers=headers, params=params, verify=verify)
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                print(f"{e}.. Trying Again.. attempt({pingcon})")
                time.sleep(3)
                if pingcon > 3:
                    print(e)
                    sys.exit(1)
                pingcon += 1
            else:
                break
        return response

    def getResource(self, resource):
        '''
        Use this method with for loop for each iteration it returns a list of resources
        The resource can be one of 'apps','scans','vulnerabilities'
        '''
        url = self.endpoints[resource]
        while True:
            response = self.get(url, headers=self.__headers)
            if response.status_code != 200:
                print(f"Something went wrong while getting {resource}..")
                print(response.text)
                sys.exit(1)
            response = response.json()
            data = response["data"]
            #print(url)
            yield data
            for link in response['links']:
                if link['rel'] == 'next':
                    url = link['href']
                    break
            else:
                break
    
    def extractScanId(request):
        try:
            _, headers = request.split('\r\n', 1)
            message = email.message_from_file(StringIO(headers))
            headers = dict(message.items())
        except:
            return ""
        return headers.get("X-RTC-SCANID","")

    def vulnerabilityMatches(vulnerability, appId, scanId, scanStarted, scanEnded):
        if vulnerability["app"]["id"] == appId:
            variances = vulnerability["variances"]
            scan_id = ""
            if "original_exchange" in vulnerability["variances"][0].keys():
                request = variances[0]["original_exchange"]["request"]
                scan_id = InsightAppSec.extractScanId(request)
            if scan_id == "" and "attack_exchanges" in vulnerability["variances"][0].keys():
                request = variances[0]["attack_exchanges"][0]["request"]
                scan_id = InsightAppSec.extractScanId(request)
            if scan_id == "":
                scan_started = parseDate(scanStarted)
                scan_ended = parseDate(scanEnded)
                last_discovered = parseDate(vulnerability["last_discovered"])
                print(scan_started, last_discovered, scan_ended)
                print("vulnerability id: ", vulnerability['id'])
                if scan_started <= last_discovered <= scan_ended:
                    return True
                else:
                    print("#"*50)
                    print("vulnerability date not in range")
                    print(vulnerability['insight_ui_url'])
                    print("#"*50)
                    return False
            if scan_id == scanId:
                return True
            else:
                return False
        return False

    def getVulnerabilities(self, appId, scanId, scanStarted, scanEnded):
        print(f"Filtering vulnerabilities for a given scan id: {scanId}")
        print("It may take few minutes...")
        all_vulnerabilities = [
            [
                "App_Name",
                "App_Id",
                "Scan_Id",
                "Scan_Status",
                "Root_Cause_Url",
                "Method",
                "Severity",
                "Status",
                "Vulnerability_Score",
                "Insight_UI_Url"
            ]
        ]
        data = self.getResource('vulnerabilities')
        for vulnerabilities in data:
            for vulnerability in vulnerabilities:
                vuln_record = []
                if InsightAppSec.vulnerabilityMatches(vulnerability, appId, scanId, scanStarted, scanEnded):
                    all_vulnerabilities.append(vulnerability)
        
        #df.to_excel('pandas_to_excel_no_index_header.xlsx', index=False, header=False)
        return all_vulnerabilities

    def getAppIdByName(self, name):
        for apps in self.getResource('apps'):
            for app in apps:
                if app['name'] == name:
                    return app['id']
            else:
                return ""
    
    def getLatestScanByAppId(self, appId):
        '''
        Returns latest Scan Object which contains scan_id, submit_time and completion_time
        '''
        data = self.getResource('scans')
        for scans in data:
            for scan in scans:
                if appId == scan['app']['id'] and scan["status"] == "COMPLETE":
                    return InsightAppSec.Scan(scan["id"], scan["status"], scan["submit_time"], scan["completion_time"])
        else:
            return None
    
    def getModule(self, moduleId):
        url = self.endpoints['module'] + f'/{moduleId}'
        response = self.get(url, headers=self.__headers)
        if response.status_code != 200:
            print(f"Something went wrong while getting module details..")
            print(response.text)
            sys.exit(1)
        return response.json()
    
    def getAttack(self, moduleId, attackId):
        url = self.endpoints['module'] + f'/{moduleId}/attacks/{attackId}'
        response = self.get(url, headers=self.__headers)
        if response.status_code != 200:
            print(f"Something went wrong while getting attack details..")
            print(response.text)
            sys.exit(1)
        return response.json()
    
    def getAttackDocumentation(self, moduleId, attackId):
        url = self.endpoints['module'] + f'/{moduleId}/attacks/{attackId}/documentation'
        response = self.get(url, headers=self.__headers)
        if response.status_code != 200:
            print(f"Something went wrong while getting attack documentation details..")
            print(response.text)
            sys.exit(1)
        return response.json()
    
    def getModuleDetails(self, moduleId, attackId, allDetails=False):
        if moduleId == '':
            module = {}
        if moduleId == '' and attackId == '':
            attack = {}
            attack_documentation = {}
        if moduleId and attackId:
            module = self.getModule(moduleId)
            attack = self.getAttack(moduleId, attackId)
            attack_documentation = self.getAttackDocumentation(moduleId, attackId)
            attack_documentation['description'] = ' '.join(BeautifulSoup(attack_documentation.get("description", ""), "lxml").text.split())
            attack_documentation['recommendation'] = ' '.join(BeautifulSoup(attack_documentation.get("recommendation", ""), "lxml").text.split())
        #print(json.dumps(attack_documentation, indent=4))
        if allDetails:
            return {
                "module": module,
                "attack": attack,
                "attack_documentation": attack_documentation
            }
        else:
            return {
            "module_id": module.get("id", ""),
            "module_name": module.get("name", ""),
            "module_description": module.get("description", ""),
            "attack_id": attack.get("id", ""),
            "attack_type": attack.get("type", ""),
            "attack_class": attack.get("class", ""),
            "attack_description": attack.get("description", ""),
            "attack_documentation_references": attack_documentation.get("references", ""),
            "attack_documentation_description": attack_documentation.get("description", ""),
            "attack_documentation_recommendation": attack_documentation['recommendation']
        }
    
    def getModuleDetailsFromRegister(self, module_id, attack_id):
        if module_id in self.__modules:
            # add the attack if not in register
            if attack_id not in self.__modules[module_id]["attacks"]:
                attack_details = self.getAttack(module_id, attack_id)
                attack_docs = self.getAttackDocumentation(module_id, attack_id)
                attack_docs['description'] = ' '.join(BeautifulSoup(attack_docs.get("description", ""), "lxml").text.split())
                attack_docs['recommendation'] = ' '.join(BeautifulSoup(attack_docs.get("recommendation", ""), "lxml").text.split())
                self.__modules[module_id]["attacks"][attack_id] = {
	                "type": attack_details.get('type', ''),
	                "class": attack_details.get('class', ''),
	                "attack_description": attack_details.get('description', ''),
                    "refrences": attack_docs.get('references', {}),
	                "description": attack_docs.get('description', ''),
	                "recommendation": attack_docs.get('recommendation', '')
                }
            else:
                #print("\nLocal")
                pass
            # retrive the attack details
            attack = self.__modules[module_id]["attacks"][attack_id]
            module_details = {
                "module_id": module_id,
                "module_name": self.__modules[module_id].get("name", ""),
                "module_description": self.__modules[module_id].get("description", ""),
                "attack_id": attack_id,
                "attack_type": attack.get("type", ""),
                "attack_class": attack.get("class", ""),
                "attack_description": attack.get("attack_description", ""),
                "attack_documentation_references": attack.get("references", ''),
                "attack_documentation_description": attack.get("description", ""),
                "attack_documentation_recommendation": attack.get('recommendation', '')
            }
        else:
            # if there is no module in register get all the details module,attack,attack_documentation
            module_details = self.getModuleDetails(module_id, attack_id)
            # add the new module to the self.__modules register
            self.__modules[module_id] = {
                "name": module_details.get("module_name", ""),
                "id": module_details.get("module_id", ""),
                "description": module_details.get("module_description", ""),
                "attacks": {
                    attack_id: {
	                    "type": module_details.get("attack_type", ""),
	                    "class": module_details.get("attack_class", ""),
	                    "attack_description": module_details.get("attack_description", ""),
                        "refrences": module_details.get("attack_documentation_references", ""),
	                    "description": module_details.get("attack_documentation_description", ""),
	                    "recommendation": module_details.get("attack_documentation_recommendation", "")
	                }
                }
            }
        return module_details
    
    def getModuleRegister(self):
        return self.__modules
    
    def getLatestVulnerabilityReport(self, appName, fileName="", appId=None, vulnerabilities_list=None):
        if not appId:
            appId = self.getAppIdByName(appName)
        if not appId:
            print(f"App {appName} doesn't exist.")
            sys.exit(1)
        scan = self.getLatestScanByAppId(appId)
        if scan == None:
            return None
        print(f"Filtering vulnerabilities of {appName}, for a given scan id: {scan.id}")
        print("It may take few minutes...")
        all_vulnerabilities = [
            [
                "App_Name",
                "App_Id",
                "Scan_Id",
                "Root_Cause_Url",
                "Method",
                "Parameter",
                "Severity",
                "Status",
                "Vulnerability_Id",
                "Vulnerability_Score",
                "Insight_UI_Url",
                "Module_Name",
                "Module_Description",
                "Attack_Vector",
                "Attack_Id",
                "Attack_Value",
                "Attack_Description",
                "Recommendation"
            ]
        ]
        if vulnerabilities_list != None:
            data = vulnerabilities_list
            print('Vulnerability List Provided..')
        else:
            data = self.getResource('vulnerabilities')
        for vulnerabilities in data:
            for vulnerability in vulnerabilities:
                vuln_record = []
                if InsightAppSec.vulnerabilityMatches(vulnerability, appId, scan.id, scan.submit_time, scan.completion_time):
                    vuln_record.extend([appName, appId, scan.id])
                    module_id = vulnerability["variances"][0]["module"]["id"] if vulnerability.get("variances") else ""
                    attack_id = vulnerability["variances"][0]["attack"]["id"] if vulnerability.get("variances") else ""
                    if module_id and attack_id:
                        module_details = self.getModuleDetailsFromRegister(module_id, attack_id)
                    else:
                        continue
                    vuln = InsightAppSec.Vulnerability(vulnerability, module_details)
                    
                    vuln_record.extend([
                        vuln.root_cause_url,
                        vuln.method,
                        vuln.parameter,
                        vuln.severity,
                        vuln.status,
                        vuln.id,
                        vuln.score,
                        vuln.insight_url,
                        vuln.module_name,
                        vuln.module_description,
                        vuln.vector,
                        vuln.attack_id,
                        vuln.attack_value,
                        vuln.attack_description,
                        vuln.recommendation
                    ])
                    all_vulnerabilities.append(vuln_record)
        if fileName:
            file_name = f"{slugify(fileName)}.xlsx"
        else:
            file_name = f"{slugify(appName)}.xlsx"

        df = pd.DataFrame(all_vulnerabilities)
        df.to_excel(file_name, index=False, header=False)
        print("file:", file_name)
        return file_name

if __name__ == "__main__":
    program_time = time.time()
    api_key = os.environ.get('API_KEY')
    ias = InsightAppSec(api_key)
    start_time = time.time()
    app_dict = {}
    for apps in ias.getResource('apps'):
        for app in apps:
            app_dict[app["id"]] = {"data": [], "name": app["name"]}
    print("app_dict initilized..")
    for data in ias.getResource('vulnerabilities'):
        for vuln in data:
            app_dict[vuln["app"]["id"]]["data"].append(vuln)
    #vulns_list = [page for page in ias.getResource('vulnerabilities')]
    print(f"Created lookup dictionary in {time.time() - start_time} seconds")
    for app in app_dict:
        start_time = time.time()
        print("vulnerabilities:", len(app_dict[app]["data"]))
        print(f"App Name: {app_dict[app]['name']}, App ID: {app}")
        file_name = ias.getLatestVulnerabilityReport(app_dict[app]["name"], appId=app, vulnerabilities_list=[app_dict[app]["data"]])
        print(f"Downloaded: {file_name}")
        print(f"Took {time.time() - start_time} seconds for app {app_dict[app]['name']}")
    
    print(f"Total Program Time: {time.time() - program_time} seconds.")
  

