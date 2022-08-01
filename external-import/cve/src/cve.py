# coding: utf-8

import gzip
import os
import shutil
import ssl
import time
import re
import urllib.request
from datetime import datetime
from natsort import natsorted
from operator import itemgetter
import certifi
import yaml
import stix2
from cvetostix2 import convert
from pycti import OpenCTIConnectorHelper, OpenCTIApiWork, get_config_variable, Infrastructure, Identity


class Cve:
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
        self.cve_import_history = get_config_variable(
            "CVE_IMPORT_HISTORY", ["cve", "import_history"], config, False
        )
        self.cve_nvd_data_feed = get_config_variable(
            "CVE_NVD_DATA_FEED", ["cve", "nvd_data_feed"], config
        )
        self.cve_history_data_feed = get_config_variable(
            "CVE_HISTORY_DATA_FEED", ["cve", "history_data_feed"], config
        )
        self.cve_interval = get_config_variable(
            "CVE_INTERVAL", ["cve", "interval"], config, True
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
        return int(self.cve_interval) * 60 * 60


    def calculate_associated_cpes(self, added_cve):
        try:
            last_index = self.helper.api.infrastructure.list(getAll=True,customAttributes="""id x_opencti_cpe_cpe23""")
            new_cpe_sorted = natsorted(last_index, key=itemgetter(*['x_opencti_cpe_cpe23']))
            for v in added_cve:
                if("CVE" in v[1]):
                    list_associated_cpe = []
                    cpess = v[2]
                    if(cpess != "" and cpess is not None):
                        cpes = cpess.split(",")
                        for cpe in cpes:
                            try:
                                i_start = ''
                                i_end = ''
                                # Extract and find the different associated CPEs
                                if("versionStartIncluding" in cpe or "versionStartExcluding" in cpe or "versionEndIncluding" in cpe or "versionEndExcluding" in cpe):
                                    if("versionStartIncluding" in cpe):
                                        cpe_versionStartIncluding = cpe.split("|")[1].replace("versionStartIncluding :","").strip()
                                        new_cpe = cpe.split("|")[0].split(":")
                                        new_cpe[5] = cpe_versionStartIncluding
                                        cpe_versionStartIncluding = ":".join(new_cpe).strip()
                                        for i in new_cpe_sorted:
                                            if(i["x_opencti_cpe_cpe23"] == cpe_versionStartIncluding):
                                                i_start = new_cpe_sorted.index(i)
                                                break
                                        if(i_start == ""):
                                            min_length = int(len(":".join(new_cpe[:5]).strip() + ":"))
                                            while(i_start == "" and len(cpe_versionStartIncluding)>=min_length):
                                                for i in new_cpe_sorted:
                                                    if(cpe_versionStartIncluding in i["x_opencti_cpe_cpe23"]):
                                                        i_start = new_cpe_sorted.index(i) 
                                                        break
                                                cpe_versionStartIncluding = cpe_versionStartIncluding[:-1]

                                    elif("versionStartExcluding" in cpe):
                                        cpe_versionStartExcluding = cpe.split("|")[1].replace("versionStartExcluding :","").strip()
                                        new_cpe = cpe.split("|")[0].split(":")
                                        new_cpe[5] = cpe_versionStartExcluding
                                        cpe_versionStartExcluding = ":".join(new_cpe).strip()
                                        for i in new_cpe_sorted:
                                            if(i["x_opencti_cpe_cpe23"] == cpe_versionStartExcluding):
                                                i_start = new_cpe_sorted.index(i) + 1
                                                break
                                        if(i_start == ""):
                                            min_length = int(len(":".join(new_cpe[:5]).strip() + ":"))
                                            while(i_start == "" and len(cpe_versionStartExcluding)>=min_length):
                                                for i in new_cpe_sorted:
                                                    if(cpe_versionStartExcluding in i["x_opencti_cpe_cpe23"]):
                                                        i_start = new_cpe_sorted.index(i) + 1
                                                        break
                                                cpe_versionStartExcluding = cpe_versionStartExcluding[:-1]


                                    elif("versionEndIncluding" in cpe or "versionEndExcluding" in cpe):
                                        new_cpe = cpe.split("|")[0].split(":")
                                        cpe_versionStart_pref = ":".join(new_cpe[:5]).strip() + ":"
                                        for i in new_cpe_sorted:
                                            if(cpe_versionStart_pref in i["x_opencti_cpe_cpe23"]):
                                                i_start = new_cpe_sorted.index(i) 
                                                break
                                    
                                    if("versionEndIncluding" in cpe):
                                        index = 0
                                        for i in cpe.split("|"):
                                            index += 1
                                            if('versionEndIncluding' in i):
                                                nbr = index
                                                break
                                        cpe_versionEndIncluding = cpe.split("|")[nbr-1].replace("versionEndIncluding :","").strip()
                                        new_cpe = cpe.split("|")[0].split(":")
                                        new_cpe[5] = cpe_versionEndIncluding
                                        cpe_versionEndIncluding = ":".join(new_cpe).strip()
                                        for i in new_cpe_sorted:
                                            if(i["x_opencti_cpe_cpe23"] == cpe_versionEndIncluding):
                                                i_end = new_cpe_sorted.index(i) + 1
                                                break
                                        if(i_end == ""):
                                            min_length = int(len(":".join(new_cpe[:5]).strip() + ":"))
                                            while(i_end == "" and len(cpe_versionEndIncluding)>=min_length):
                                                for i in reversed(new_cpe_sorted):
                                                    if(cpe_versionEndIncluding in i["x_opencti_cpe_cpe23"]):
                                                        i_end = new_cpe_sorted.index(i) + 1
                                                        break
                                                cpe_versionEndIncluding = cpe_versionEndIncluding[:-1]

                                    elif("versionEndExcluding" in cpe):
                                        index = 0
                                        for i in cpe.split("|"):
                                            index += 1
                                            if('versionEndExcluding' in i):
                                                nbr = index
                                                break
                                        cpe_versionEndExcluding = cpe.split("|")[nbr-1].replace("versionEndExcluding :","").strip()
                                        new_cpe = cpe.split("|")[0].split(":")
                                        new_cpe[5] = cpe_versionEndExcluding
                                        cpe_versionEndExcluding = ":".join(new_cpe).strip()
                                        for i in new_cpe_sorted:
                                            if(i["x_opencti_cpe_cpe23"] == cpe_versionEndExcluding):
                                                i_end = new_cpe_sorted.index(i) + 1
                                                break
                                        if(i_end == ""):
                                            min_length = int(len(":".join(new_cpe[:5]).strip() + ":"))
                                            while(i_end == "" and len(cpe_versionEndExcluding)>=min_length):
                                                for i in reversed(new_cpe_sorted):
                                                    if(cpe_versionEndExcluding in i["x_opencti_cpe_cpe23"]):
                                                        i_end = new_cpe_sorted.index(i) + 1
                                                        break
                                                cpe_versionEndExcluding = cpe_versionEndExcluding[:-1]

                                    elif("versionStartIncluding" in cpe or "versionStartExcluding" in cpe):
                                        new_cpe = cpe.split("|")[0].split(":")
                                        cpe_versionEnd_pref = ":".join(new_cpe[:5]).strip() + ":"
                                        for i in reversed(new_cpe_sorted):
                                            if(cpe_versionEnd_pref in i["x_opencti_cpe_cpe23"]):
                                                i_end = new_cpe_sorted.index(i)
                                                break

                                    if(i_start == "" and i_end == ""):
                                        self.helper.log_error(
                                        "Missing CPE : {}".format(cpe)
                                        )
                                        continue
                                    list_associated_cpe.append(new_cpe_sorted[i_start:i_end])
                                else:
                                    for i in new_cpe_sorted:
                                        if(cpe in i["x_opencti_cpe_cpe23"]):
                                            list_associated_cpe.append([i])
                                    
                            except Exception as e:
                                self.helper.log_error("Error : " + str(e))
                        result = ""
                        # Create the relationship
                        try:
                            if(int(len(str(list_associated_cpe)) > 2)):
                                for i in range(0,len(list_associated_cpe)):
                                    for item in range(0,len(list_associated_cpe[i])):
                                        id = list_associated_cpe[i][item]
                                        result = result + id["x_opencti_cpe_cpe23"] + ","
                                        self.helper.api.stix_core_relationship.create(
                                                        fromId=id["id"],
                                                        toId=v[0],
                                                        relationship_type="related-to",
                                                        description=id["id"] + " has the vulnerability " + v[0],
                                                        confidence=int(self.confidence_level),
                                                        update=True,
                                            )
                                if(result != ''):
                                    result = result[:-1]
                                    self.helper.api.stix_domain_object.update_field(
                                        id=v[0], input={"key": "x_opencti_related_cpe", "value": result}
                                    )
                            else: 
                                self.helper.api.stix_domain_object.update_field(
                                        id=v[0], input={"key": "x_opencti_related_cpe", "value": result}
                                    )
                        except Exception as e:
                            self.helper.log_error(
                                "Error with CPE relationship creation : " + str(e)
                            )
        except Exception as e:
            self.helper.log_error(
                "Error : " + str(e)
            )  

    def add_meta(self, added_cve):
        # Assign data to CVE
        for item in added_cve:
            # Confidence
            self.helper.api.stix_domain_object.update_field(
                id=item[0], input={"key": "confidence", "value": str(self.confidence_level)}
            )

    def delete_files(self):
        if os.path.exists("data.json"):
            os.remove("data.json")
        if os.path.exists("data.json.gz"):
            os.remove("data.json.gz")
        if os.path.exists("data-stix2.json"):
            os.remove("data-stix2.json")

    def convert_and_send(self, url, work_id):
        try:
            # Downloading json.gz file
            self.helper.log_info("Requesting the file " + url)
            response = urllib.request.urlopen(
                url, context=ssl.create_default_context(cafile=certifi.where())
            )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.json.gz", "wb"
            ) as file:
                file.write(image)
            # Unzipping the file
            self.helper.log_info("Unzipping the file")
            with gzip.open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.json.gz", "rb"
            ) as f_in:
                with open("data.json", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            # Converting the file to stix2
            self.helper.log_info("Converting the file")
            added_cve = convert("data.json", "data-stix2.json")
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
            # Create the relationships
            for cve in added_cve:
                try:
                    req_cve = self.helper.api.vulnerability.read(filters=[{"key": "name", "values": [cve[1]]}])
                    if(len(req_cve["x_opencti_cwe"])>0):
                        for cwe in req_cve["x_opencti_cwe"].split(','):
                            req_cwe = self.helper.api.attack_pattern.read(filters=[{"key": "name", "values": [cwe.strip()]}])
                            self.helper.api.stix_core_relationship.create(
                                fromId=req_cwe["id"],
                                toId=req_cve["id"],
                                relationship_type="targets",
                                description=req_cve["name"] + " uses " + req_cwe["name"],
                                confidence=int(self.confidence_level),
                                update=True,
                            )
                except Exception as e:
                    self.helper.log_error("Error with " + cve[1] + " : " + str(e))
                    pass
                    
            self.add_meta(added_cve)
            self.calculate_associated_cpes(added_cve)
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
            # If the last_run is more than interval (in hours)
            if last_run is None or (
                (timestamp - last_run) > ((int(self.cve_interval) - 1) * 60 * 60)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "CVE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.convert_and_send(self.cve_nvd_data_feed, work_id)
               
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
        self.helper.log_info("Fetching CVE knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        cveConnector = Cve()
        cveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
