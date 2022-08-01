# coding: utf-8

import os
import time
from datetime import datetime
import requests
import lxml.html
from random import randint
import re
import json
import base64
from bs4 import BeautifulSoup
import stix2
import certifi
import yaml
from pycti import OpenCTIConnectorHelper, OpenCTIApiWork, get_config_variable, Identity, Malware
import traceback

class CxSecurity:

    headers = {'User-Agent': 'Mozilla/5.0'}

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.worker = OpenCTIApiWork(self.helper.api)
        # Extra config
        self.cxsecurity_interval = get_config_variable(
            "CXSECURITY_FULL_INTERVAL", ["cxsecurity", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
        )
        self.label_color = get_config_variable(
            "CONNECTOR_LABEL_COLOR",
            ["connector", "label_color"],
            config,
        )

    def get_interval(self):
        return int(self.cxsecurity_interval) * 60 * 60 * 24

    def add_meta(self):
        # Get all the exploits
        req_list_malware = self.helper.api.malware.list(getAll=True,customAttributes="""id x_opencti_malware_cve description""",filters=[{"key": "malware_types", "values": "exploit-kit"}])
        # Assign data to exploit
        for item in req_list_malware:
            try:
                if("CXSecurity" in item["description"]):
                    # Confidence
                    self.helper.api.stix_domain_object.update_field(
                        id=item["id"], input={"key": "confidence", "value": str(self.confidence_level)}
                    )
                    # Label
                    new_label_source = self.helper.api.label.create(
                                value="CXSecurity", color=self.label_color
                    )
                    self.helper.api.stix_domain_object.add_label(
                                id=item["id"], label_id=new_label_source["id"]
                    )
                    # Correlated with a CVE
                    if(item["x_opencti_malware_cve"] != "" and item["x_opencti_malware_cve"] != 'N/A'):
                        # Label
                        new_label_cve = self.helper.api.label.create(
                                    value=item["x_opencti_malware_cve"], color=self.label_color
                        )
                        self.helper.api.stix_domain_object.add_label(
                                    id=item["id"], label_id=new_label_cve["id"]
                        )
                        # Create the relationship between the vendor and the infrastructure
                        req_cve = self.helper.api.vulnerability.read(filters=[{"key": "name", "values": [item["x_opencti_malware_cve"]]}])
                        if(req_cve is not None and req_cve != 'N/A'):
                            self.helper.api.stix_core_relationship.create(
                                fromId=item["id"],
                                toId=req_cve["id"],
                                relationship_type="exploits",
                                description=item["id"] + " exploits the vulnerability " + item["x_opencti_malware_cve"],
                                confidence=int(self.confidence_level),
                                update=True,
                            )
            except Exception as e:
                self.helper.log_info("Error with " + item["x_opencti_malware_cve"] + " : " + str(e))
                pass


    def list_exploits(self):
        list_issues = []
        # Index the most recent issue
        page = requests.get(url="https://cxsecurity.com/wlb/published/1", headers=self.headers)
        soup = BeautifulSoup(page.content, "html.parser")
        most_recent = soup.find_all('a', href=re.compile('https://cxsecurity.com/issue/'))[0]['href']
        for a in soup.find_all('a', href=re.compile('https://cxsecurity.com/issue/')):
            list_issues.append(a['href'])

        # Get the list of all the issues on the website
        end = False 
        i = 2
        while(end == False):
            page = requests.get(url="https://cxsecurity.com/wlb/published/" + str(i), headers=self.headers)
            soup = BeautifulSoup(page.content, "html.parser")
            # Extract the issue links of the page
            if(soup.find_all('a', href=re.compile('https://cxsecurity.com/issue/'))[0]['href'] == most_recent):
                end = True 
                break 
            else:
                for a in soup.find_all('a', href=re.compile('https://cxsecurity.com/issue/')):
                    list_issues.append(a['href'])
            i += 1
            if(i % 60 == 0):
                time.sleep(3600)
        return list_issues
        

    def fetch_and_send(self, work_id):
        self.helper.log_info("Fetching of the CXSecurity list of issues")
        list = self.list_exploits()
        try:
            index = 0
            bundle_to_send = []
            # Create the identity of CXSecurity
            cxsec_identity = stix2.Identity(
                id=Identity.generate_id("CXSecurity", "organization"),
                name="CXSecurity",
                identity_class="organization",
            )
            bundle_to_send.append(cxsec_identity)
            for url in list:
                self.helper.log_info("Fetching of the CXSecurity : " + url)
                try:
                    index += 1
                    if(index % 60 == 0):
                        time.sleep(3600)
                    cve = ""
                    response = requests.get(url=url, headers=self.headers)
                    response.encoding = 'utf-8'
                    html = lxml.html.fromstring(response.content)
                    title = html.xpath('//h4/b')[0].text_content()
                    if(title == "" or title is None):
                        title = "Unknown"
                    date = html.xpath('//div[@class="col-xs-12 col-md-3"]/div[@class="well well-sm"]/b')[0].text_content().strip()
                    author = html.xpath('//div[@class="col-xs-12 col-md-6"]/div[@class="well well-sm"]/b/a')[0].text_content().strip()
                    risk = html.xpath('//div[@class="col-xs-5 col-md-3"]/div[@class="well well-sm"]/b')[0].text_content().strip()
                    local = html.xpath('//div[@class="col-xs-3 col-md-3"]/div[@class="well well-sm"]/b')[0].text_content().strip()
                    remote = html.xpath('//div[@class="col-xs-4 col-md-3"]/div[@class="well well-sm"]/b')[0].text_content().strip()
                    mitre = html.xpath('//div[@class="col-xs-6 col-md-3"]/div[@class="well well-sm"]/b')[:-1]
                    for c in mitre:
                        cve = cve + c.text_content().strip()
                    cwe = html.xpath('//div[@class="col-xs-6 col-md-3"]/div[@class="well well-sm"]/b')[-1].text_content().strip()
                    code = requests.get(url=url.replace("issue","ascii"), headers=self.headers).text.split('<PRE>')[1].split('</PRE>')[0].lstrip().rstrip()
                    # Create external references
                    external_reference = stix2.ExternalReference(
                        source_name="CXSecurity", url=url
                    )
                    external_references = [external_reference]
                    # Creating the malware with the extracted fields
                    malw = stix2.Malware(
                        id=Malware.generate_id(title),
                        name=title,
                        first_seen=datetime.strptime(date,"%Y.%m.%d"),
                        description="CXSecurity : " + title,
                        malware_types='exploit-kit',
                        is_family=False,
                        external_references=external_references,
                        custom_properties={
                            "x_opencti_malware_cve": cve,
                            "x_opencti_malware_risk": risk,
                            "x_opencti_malware_local": local,
                            "x_opencti_malware_remote": remote,
                            "x_opencti_malware_code": code,
                        },
                    )
                    bundle_to_send.append(malw)
                except Exception as e:
                    self.helper.log_info("Error " + str(e) + " with the URL " + url)
                if(index == 5000):
                    bundle = stix2.Bundle(bundle_to_send, allow_custom=True)
                    bundle_json = bundle.serialize()
                    self.helper.send_stix2_bundle(
                        bundle_json,
                        entities_types=self.helper.connect_scope,
                        update=self.update_existing_data,
                        work_id=work_id,
                    )
                    index = 0
                    bundle_to_send = []
            bundle = stix2.Bundle(bundle_to_send, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                        bundle_json,
                        entities_types=self.helper.connect_scope,
                        update=self.update_existing_data,
                        work_id=work_id,
            )
            self.worker.wait_for_work_to_finish(work_id)
            self.add_meta()
        except Exception as e:
            print(traceback.format_exc())
            self.helper.log_error(str(e))
            time.sleep(60)


    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval (in days)
            if last_run is None or (
                (timestamp - last_run) > ((int(self.cxsecurity_interval) - 1) * 60 * 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "CXSecurity run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.fetch_and_send(work_id)
               
                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching CXSecurity knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        CxSecurityConnector = CxSecurity()
        CxSecurityConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
