# coding: utf-8

import zipfile
import os
import ssl
import time
import urllib.request
import json
import glob
from datetime import datetime

import certifi
import yaml
from cwetostix2 import convert
from pycti import OpenCTIConnectorHelper, OpenCTIApiWork, get_config_variable

class Cwe:
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
        self.cwe_mitre_data_feed = get_config_variable(
            "CWE_MITRE_DATA_FEED", ["cwe", "mitre_data_feed"], config
        )
        self.cwe_interval = get_config_variable(
            "CWE_INTERVAL", ["cwe", "interval"], config, True
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
        return int(self.cwe_interval) * 60 * 60

    def delete_files(self):
        if os.path.exists("cwec_latest.xml.zip"):
            os.remove("cwec_latest.xml.zip")
        file_list = glob.glob('*.xml')
        for f in file_list:
            os.remove(f)
        if os.path.exists("data-stix2.json"):
            os.remove("data-stix2.json")

    def add_meta(self):
        # Get all the CWEs
        req_list_cwes = self.helper.api.attack_pattern.list(getAll=True,customAttributes="""id name""")
        index = -1
        list_cwes_id = []
        list_cwes_name = []
        while True:
            try:
                index += 1
                if('CWE' in req_list_cwes[index]['name']):
                    list_cwes_id.append(req_list_cwes[index]['id'])
                    list_cwes_name.append(req_list_cwes[index]['name'])
            except:
                break
        # Assign data to CWE
        index = -1
        for item in list_cwes_id:
            index += 1
            # Confidence
            self.helper.api.stix_domain_object.update_field(
                id=item, input={"key": "confidence", "value": str(self.confidence_level)}
            )
            # Label
            new_label = self.helper.api.label.create(
                        value=list_cwes_name[index], color=self.label_color
            )
            self.helper.api.stix_domain_object.add_label(
                        id=item, label_id=new_label["id"]
            )

    def convert_and_send(self, url, work_id):
        try:
            # Downloading zip file
            self.helper.log_info("Requesting the file " + url)
            response = urllib.request.urlopen(
                url, context=ssl.create_default_context(cafile=certifi.where())
            )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/cwec_latest.xml.zip", "wb"
            ) as file:
                file.write(image)
            # Unzipping the file
            self.helper.log_info("Unzipping the file")
            with zipfile.ZipFile("cwec_latest.xml.zip","r") as zip_ref:
                zip_ref.extractall(".")
            # List new extacted file
            file_list = glob.glob('*.xml')
            # Converting the file to stix2
            self.helper.log_info("Converting the file")
            convert(file_list[0], "data-stix2.json")
            with open("data-stix2.json") as stix_json:
                contents = stix_json.read()
                self.helper.send_stix2_bundle(
                    contents,
                    entities_types=self.helper.connect_scope,
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            stix_json.close()
            self.worker.wait_for_work_to_finish(work_id)
            self.add_meta()
            # Remove files
            self.delete_files()
        except Exception as e:
            self.delete_files()
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
            # If the last_run is more than interval-1 hour
            if last_run is None or (
                (timestamp - last_run) > ((int(self.cwe_interval) - 1) * 60 * 60)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "CWE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.convert_and_send(self.cwe_mitre_data_feed, work_id)
               
                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60, 2))
                    + " hours"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60, 2))
                    + " hours"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching CWE knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        cweConnector = Cwe()
        cweConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
