import sqlite3
from sqlite3 import Error

import pandas as pd

import os
import sys
import itertools
import threading
import time
import sys
import json

from .insightappsec import InsightAppSec

class AppSecDB:
    def __init__(self, file_name):
        self.apps_table = "Apps"
        self.scans_table = "Scans"
        self.vulnerabilities_table = "Vulnerabilities"
        self.ias = InsightAppSec(os.environ.get('API_KEY'))
        self.__con = None
        self.__cur = None
        self.file = file_name
        if file_name == ":memory:":
            self.__con = self.createInMemoryConnection()
        else:
            self.__con = self.createConnection(self.file)
        self.__cur = self.__con.cursor()
        self.__cur.execute("PRAGMA foreign_keys = ON")

    def createInMemoryConnection(self):
        try:
            connection = sqlite3.connect(":memory:")
            print("InMemory DB: Created")
        except Error as e:
            print(f"The error '{e}' occurred: Terminated")
            sys.exit(1)
        self.initialize(connection)
        return connection

    def createConnection(self, file_name):
        connection = None
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(ROOT_DIR, file_name)
        try:
            connection = sqlite3.connect(f"file:{file_path}?mode=rw", uri=True)
            print("Connection to DB: successful")
        except Error as e:
            #print(f"The error '{e}' occurred")
            connection = sqlite3.connect(file_path)
            print("New Database: Created")
            self.initialize(connection)
        return connection

    def initialize(self, con):
        # Creates Teams table (Team_Name, Team_Owner)
        # Creates Repos table (Repo_Name, Team, Team_POC)
        ##
        # FOREIGN KEY(Team) REFERENCES Teams (Team_Name)
        q_script = '''
            CREATE TABLE IF NOT EXISTS Apps (
                App_Id TEXT PRIMARY KEY NOT NULL,
                App_Name TEXT
            );

            CREATE TABLE IF NOT EXISTS Scans (
                Scan_Id TEXT PRIMARY KEY NOT NULL,
                App_Id TEXT NOT NULL,
                App_Name TEXT NOT NULL,
                Submit_Time TEXT,
                Completion_Time TEXT,
                Status TEXT,
                Failure_Reason TEXT
            );

            CREATE TABLE IF NOT EXISTS Vulnerabilities (
                Vuln_Id TEXT PRIMARY KEY NOT NULL,
                App_Id TEXT,
                Scan_Id TEXT,
                Root_Cause_Url TEXT,
                Method TEXT,
                Parameter TEXT,
                Severity TEXT,
                First_Discovered TEXT,
                Last_Discovered TEXT,
                Module_Id TEXT,
                Module_Name TEXT,
                Module_Description TEXT,
                Attack_Id TEXT,
                Attack_Value TEXT,
                Attack_Description TEXT,
                Attack_Recommendation TEXT,
                Attack_Vector TEXT,
                Vulnerability_Score REAL,
                Insight_UI_Url TEXT
            );

            CREATE TABLE IF NOT EXISTS Modules (
                Module_Id TEXT PRIMARY KEY NOT NULL,
                Module_Name TEXT,
                Module_Description TEXT
            );

            CREATE TABLE IF NOT EXISTS Attacks (
                Attack_Id TEXT PRIMARY KEY NOT NULL,
                Attack_Type TEXT,
                Attack_Class TEXT,
                Attack_Description TEXT
            );

            CREATE TABLE IF NOT EXISTS AttackDocumentation (
                Attack_Id TEXT PRIMARY KEY NOT NULL,
                Attack_References TEXT,
                Description TEXT,
                Recommendation TEXT
            );
        '''
        try:
            con.executescript(q_script)
            print("Database tables initialized successfully")
        except Error as e:
            print(f"The error '{e}' occurred: Terminating")
            sys.exit(1)

    def getApps(self):
        query = "SELECT * FROM Apps"
        self.__cur.execute(query)
        return self.__cur.fetchall()

    def getScans(self):
        query = "SELECT * FROM Scans"
        self.__cur.execute(query)
        return self.__cur.fetchall()
    
    def getVulnerabilities(self):
        query = "SELECT * FROM Vulnerabilities"
        self.__cur.execute(query)
        return self.__cur.fetchall()
    
    def clearTable(self, table_name):
        if table_name == "Apps":
            query = "DELETE FROM Apps"
        elif table_name == "Scans":
            query = "DELETE FROM Scans"
        elif table_name == "Vulnerabilities":
            query = "DELETE FROM Vulnerabilities"
        else:
            print(f"Table {table_name} does not exist.")
            return None
        try:
            self.__cur.execute(query)
            self.__con.commit()
        except Error as e:
            print(f"The error '{e}' occurred")
    
    def getScansByApp(self, app_name='', app_id=''):
        if app_name:
            query = "SELECT * FROM Scans Where App_Name = (?)"
            self.__cur.execute(query, (app_name,))
            return self.__cur.fetchall()
        elif app_id:
            query = "SELECT * FROM Scans Where App_Id = (?)"
            self.__cur.execute(query, (app_id,))
            return self.__cur.fetchall()
    
    def addApp(self, app_dict):
        # Add app if doesnot exists.
        query = "INSERT INTO Apps (App_Id, App_Name) VALUES (:app_id, :app_name)"
        try:
            self.__cur.execute(query, app_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            print(f"The error '{err}' occurred")
    
    def addScan(self, scan_dict):
        # Add app if doesnot exists.
        query = "INSERT INTO Scans (Scan_Id, App_Id, App_Name, Submit_Time, Completion_Time, Status, Failure_Reason) VALUES (:scan_id, :app_id, :app_name, :submit_time, :completion_time, :status, :failure_reason)"
        try:
            self.__cur.execute(query, scan_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            print(f"The error '{err}' occurred")
    
    def addVulnerability(self, vuln_dict):
        # Add app if doesnot exists.
        query = """INSERT INTO Vulnerabilities 
        (Vuln_Id, App_Id, Scan_Id, Root_Cause_Url, Method, Parameter, 
        Severity, First_Discovered, Last_Discovered, Module_Id, Module_Name,
        Module_Description, Attack_Id, Attack_Value, Attack_Description,
        Attack_Recommendation, Attack_Vector, Vulnerability_Score,
        Insight_UI_Url) VALUES 
        (:vuln_id, :app_id, :scan_id, :root_cause_url, :method, :parameter, 
        :severity, :first_discovered, :last_discovered, :module_id,
        :module_name, :module_description, :attack_id, :attack_value,
        :attack_description, :attack_recommendation, :attack_vector,
        :vulnerability_score, :insight_ui_url)"""
        try:
            self.__cur.execute(query, vuln_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            print(f"The error '{err}' occurred")
    
    def addModule(self, module_dict):
        # Add app if doesnot exists.
        query = "INSERT INTO Modules (Module_Id, Module_Name, Module_Description) VALUES (:module_id, :module_name, :module_description)"
        try:
            self.__cur.execute(query, module_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            #print(f"The error '{err}' occurred")
            #print("module-id:",module_dict['module_id'])
            pass
    
    def addAttack(self, attack_dict):
        # Add app if doesnot exists.
        query = "INSERT INTO Attacks (Attack_Id, Attack_Type, Attack_Class, Attack_Description) VALUES (:attack_id, :attack_type, :attack_class, :attack_description)"
        try:
            self.__cur.execute(query, attack_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            #print(f"The error '{err}' occurred")
            #print("attack-id:",attack_dict['attack_id'])
            pass
    
    def addAttackDocumentation(self, attack_doc_dict):
        # Add app if doesnot exists.
        query = "INSERT INTO AttackDocumentation (Attack_Id, Attack_References, Description, Recommendation) VALUES (:attack_id, :references, :description, :recommendation)"
        try:
            self.__cur.execute(query, attack_doc_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            #print(f"The error '{err}' occurred")
            #print("attack-id:",attack_doc_dict['attack_id'])
            pass
    
    def getModule(self, module_id):
        # Select repo name from Repos table and return result
        query = "SELECT * FROM Modules WHERE Module_Id = (?)"
        try:
            self.__cur.execute(query, (module_id,))
            return self.__cur.fetchall()
        except Error as e:
            print(f"The error '{e}' occurred")
    
    def getAttack(self, attack_id):
        # Select repo name from Repos table and return result
        query = "SELECT * FROM Attacks WHERE Attack_Id = (?)"
        try:
            self.__cur.execute(query, (attack_id,))
            return self.__cur.fetchall()
        except Error as e:
            print(f"The error '{e}' occurred")
    
    def getAttackDocumentation(self, attack_id):
        # Select repo name from Repos table and return result
        query = "SELECT * FROM AttackDocumentation WHERE Attack_Id = (?)"
        try:
            self.__cur.execute(query, (attack_id,))
            return self.__cur.fetchall()
        except Error as e:
            print(f"The error '{e}' occurred")
    
    def animate(self, its):
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if its["done"]:
                break
            sys.stdout.write('\rSyncing ' + c + f'  {its["percent"]} %')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\rDone!             \n')
    
    def syncAppSecDB(self):
        # get all data and save into database
        # First clear Tables Apps, Scans, Vulnerabilities
        self.clearTable("Apps")
        self.clearTable("Scans")
        self.clearTable("Vulnerabilities")
        print("Cleared All Tables..")
        # Initialise Tables Apps and Scans
        its = {"done": False, "percent": 0}
        t = threading.Thread(target=self.animate, args=(its,))
        # t.setDaemon(True)
        t.deamon = True
        t.start()
        app_register = {}
        for apps in self.ias.getResource('apps'):
            for app in apps:
                app_register[app["id"]] = {"data": [], "name": app["name"]}
                self.addApp({"app_id": app["id"], "app_name": app["name"]})
                its["percent"] = round(its["percent"] + 100/len(apps), 1)
                time.sleep(0.1)
            its["percent"] = 0
        #its["percent"] = 100
        print("\b:Apps Synced")
        page = 0
        for scans in self.ias.getResource("scans"):
            print("\npage: ", page)
            for scan in scans:
                scan_dict = {
                    "scan_id": scan["id"],
                    "app_id": scan["app"]["id"],
                    "app_name": app_register[scan["app"]["id"]]["name"],
                    "submit_time": scan["submit_time"] if scan.get("submit_time") else '',
                    "completion_time": scan["completion_time"] if scan.get("completion_time") else '',
                    "status": scan["status"],
                    "failure_reason": scan["failure_reason"] if scan.get("failure_reason") else '',
                }
                self.addScan(scan_dict)
                its["percent"] = round(its["percent"] + 100/len(scans), 1)
            its["percent"] = 0
            page += 1
            time.sleep(0.2)
        print("\b:Scans Synced")
        page = 0
        for vulnerabilities in self.ias.getResource("vulnerabilities"):
            total_vulns = len(vulnerabilities)
            print("\npage:", page)
            for vulnerability in vulnerabilities:
                variances = vulnerability["variances"]
                module_id = vulnerability["variances"][0]["module"]["id"] if vulnerability.get("variances") else ""
                attack_id = vulnerability["variances"][0]["attack"]["id"] if vulnerability.get("variances") else ""
                ##
                # module = self.getModule(module_id)
                # attack = self.getAttack(attack_id)
                # attack_docs = self.getAttackDocumentation(attack_id)
                ##
                module_details = self.ias.getModuleDetailsFromRegister(module_id, attack_id)
                scan_id = ""
                if "original_exchange" in vulnerability["variances"][0].keys():
                    request = variances[0]["original_exchange"]["request"]
                    scan_id = InsightAppSec.extractScanId(request)
                if scan_id == "" and "attack_exchanges" in vulnerability["variances"][0].keys():
                    request = variances[0]["attack_exchanges"][0]["request"]
                    scan_id = InsightAppSec.extractScanId(request)
                vuln_dict = {
                    "vuln_id": vulnerability['id'], 
                    "app_id": vulnerability['app']['id'], 
                    "scan_id": scan_id, 
                    "root_cause_url": vulnerability["root_cause"]["url"] if vulnerability.get("root_cause") else "", 
                    "method": vulnerability["root_cause"]["method"] if vulnerability.get("root_cause") else "", 
                    "parameter": vulnerability["root_cause"]["parameter"] if vulnerability.get("root_cause", {}).get("parameter") else "", 
                    "severity": vulnerability.get("severity",""), 
                    "first_discovered": vulnerability.get("first_discovered", ""), 
                    "last_discovered": vulnerability.get("last_discovered", ""), 
                    "module_id": module_id,
                    "module_name": module_details["module_name"], 
                    "module_description": module_details["module_description"], 
                    "attack_id": attack_id, 
                    "attack_value": vulnerability["variances"][0].get("attack_value", ""),
                    "attack_description": module_details["attack_description"], 
                    "attack_recommendation": module_details["attack_documentation_recommendation"], 
                    "attack_vector": vulnerability.get("vector_string", ""),
                    "vulnerability_score": vulnerability.get("vulnerability_score", ""), 
                    "insight_ui_url": vulnerability.get("insight_ui_url", "")
                }
                self.addVulnerability(vuln_dict)
                self.addModule({
                    "module_id": module_details["module_id"],
                    "module_name":module_details["module_name"],
                    "module_description": module_details["module_description"]
                })
                self.addAttack({
                    "attack_id": module_details["attack_id"],
                    "attack_type": module_details["attack_type"],
                    "attack_class": module_details["attack_class"],
                    "attack_description": module_details["attack_description"]
                })
                self.addAttackDocumentation({
                    "attack_id": module_details["attack_id"],
                    "references": json.dumps(module_details["attack_documentation_references"]), 
                    "description": module_details["attack_documentation_description"],
                    "recommendation": module_details["attack_documentation_recommendation"]
                })
                its["percent"] = round(its["percent"] + 100/total_vulns, 1)
            its["percent"] = 0
            page += 1
        its["done"] = True
        time.sleep(1)
        print("Vulnerabilities Synced")

    def downloadReport(self, scan_id, app_id):
        pass

    def __del__(self):
        if self.__con and self.__cur:
            self.closeDB()

    def getRepoName(self, repo_name):
        # Select repo name from Repos table and return result
        query = "SELECT * FROM Repos WHERE Repo_Name = (?)"
        try:
            self.__cur.execute(query, (repo_name,))
            return self.__cur.fetchall()
        except Error as e:
            print(f"The error '{e}' occurred")

    def getTeamName(self, team_name):
        # Select team name from Teams table and return result
        query = "SELECT * FROM Teams WHERE Team_Name = (?)"
        try:
            self.__cur.execute(query, (team_name,))
            return self.__cur.fetchall()
        except Error as e:
            print(f"The error '{e}' occurred")

    def addTeam(self, team_dict):
        # Add team if doesnot exists.
        query = "INSERT INTO Teams (Team_Name, Team_Owner) VALUES (:team, :team_owner)"
        try:
            self.__cur.execute(query, team_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            if team_dict["team_owner"] != "Unknown":
                self.updateTeam(team_dict)
            #print(f"The error '{e}' occurred")

    def addRepo(self, repo_dict):
        # Add repo if doesnot exists.
        query = "INSERT INTO Repos (Repo_Name, Team, Team_POC, Risk_Score, Risk) VALUES (:repo, :team, :team_poc, :risk_score, :risk)"
        try:
            self.__cur.execute(query, repo_dict)
            self.__con.commit()
        except sqlite3.IntegrityError as err:
            #print(f"The error '{e}' occurred")
            pass

    def updateTeam(self, team_dict):
        # update team for existing team
        query = "UPDATE Teams SET Team_Owner = :team_owner WHERE Team_Name = :team"
        try:
            self.__cur.execute(query, team_dict)
            self.__con.commit()
        except Error as e:
            print(f"The error '{e}' occurred")

    def updateRepo(self, repo_dict):
        # update repo if securityconfig.json updates
        query = "UPDATE Repos SET Team = :team, Team_POC = :team_poc, Risk_Score = :risk_score, Risk = :risk WHERE Repo_Name = :repo"
        try:
            self.__cur.execute(query, repo_dict)
            self.__con.commit()
        except Error as e:
            print(f"The error '{e}' occurred")

    def deleteTeam(self, team_name):
        # delete team if it has no repos
        query = "DELETE FROM Teams WHERE Team_Name = (?)"
        try:
            self.__cur.execute(query, (team_name,))
            self.__con.commit()
        except Error as e:
            print(f"The error '{e}' occurred")

    def deleteRepo(self, repo_name):
        # delete repo if its been archived
        query = "DELETE FROM Repos WHERE Repo_Name = (?)"
        try:
            self.__cur.execute(query, (repo_name,))
            self.__con.commit()
        except Error as e:
            print(f"The error '{e}' occurred")

    def dumpCsv(self):
        df = pd.read_sql(f'SELECT * FROM Teams', self.__con)
        df.to_csv(f'{self.teams_table}.csv', index=False)
        df = pd.read_sql(f'SELECT * FROM Repos', self.__con)
        df.to_csv(f'{self.repos_table}.csv', index=False)

    def dumpExcel(self):
        df = pd.read_sql(f'SELECT * FROM Teams', self.__con)
        df.to_excel(f'{self.teams_table}.xlsx', index=False)
        df = pd.read_sql(f'SELECT * FROM Repos', self.__con)
        df.to_excel(f'{self.repos_table}.xlsx', index=False)

    def closeDB(self):
        self.__cur.close()
        self.__con.close()

    def getDB(filename=None):
        if filename:
            return AppSecDB(filename)
        else:
            return AppSecDB(":memory:")


if __name__ == "__main__":
    start_time = time.time()
    db = AppSecDB("appsec_db.db")
    db.syncAppSecDB()
    with open("register_data.json", "w") as f:
        f.write(json.dumps(db.ias.getModuleRegister()))
    print(f"It Took {time.time() - start_time} seconds")

