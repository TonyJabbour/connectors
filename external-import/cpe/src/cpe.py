# coding: utf-8

import zipfile
import os
import ssl
import time
import urllib.request
from datetime import datetime
import xml.etree.ElementTree as et
import stix2
import re
import glob
import time
import certifi
import yaml
import traceback
import threading
from pycti import OpenCTIConnectorHelper, OpenCTIApiWork, get_config_variable


class Cpe:
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
        self.cpe_nvd_data_feed = get_config_variable(
            "CPE_NVD_DATA_FEED", ["cpe", "nvd_data_feed"], config
        )
        self.cpe_interval = get_config_variable(
            "CPE_INTERVAL", ["cpe", "interval"], config, True
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

    def get_interval(self):
        return int(self.cpe_interval) * 60 * 60 * 24

    def delete_files(self):
        if os.path.exists("official-cpe-dictionary_v2.3.xml.zip"):
            os.remove("official-cpe-dictionary_v2.3.xml.zip")
        file_list = glob.glob('*.xml')
        for f in file_list:
            os.remove(f)

    def convert_and_send(self, url, work_id):
        try:
            # Downloading zip file
            self.helper.log_info("Requesting the file " + url)
            response = urllib.request.urlopen(
                url, context=ssl.create_default_context(cafile=certifi.where())
            )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/official-cpe-dictionary_v2.3.xml.zip", "wb"
            ) as file:
                file.write(image)
            # Unzipping the file
            self.helper.log_info("Unzipping the file")
            with zipfile.ZipFile("official-cpe-dictionary_v2.3.xml.zip","r") as zip_ref:
                zip_ref.extractall(".") 
            # Create the identity of the author 
            author_send = self.helper.api.identity.create(
                type='Organization',
                name='The MITRE Corporation',
                description='',
            )
            # List new extacted file
            file_list = glob.glob('*.xml')
            # Processing the file
            self.helper.log_info("Processing the file")
            with open(file_list[0]) as xml_file:
                tree = et.parse(xml_file)
                root = tree.getroot()
                for cpe in root:
                    if(cpe.tag == '{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
                        # Get the title
                        title = cpe.find('{http://cpe.mitre.org/dictionary/2.0}title').text
                        #self.helper.log_info("Processing " + title)
                        # Get the CPE
                        if(cpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').find('{http://scap.nist.gov/schema/cpe-extension/2.3}deprecation') is not None):
                            cpe23 = cpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').find('{http://scap.nist.gov/schema/cpe-extension/2.3}deprecation').find('{http://scap.nist.gov/schema/cpe-extension/2.3}deprecated-by').get('name')
                        else:
                            cpe23 = cpe.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item').get('name')
                        # Extract fields
                        vendor = ''
                        product = ''
                        version = ''
                        vendor = cpe23.split(':')[3].lower()
                        product = cpe23.split(':')[4].lower()
                        version = cpe23.split(':')[5].lower()
                        # Regex to assure coherence (ex. Silver Peak == Silver-Peak == SilverPeak)
                        vendor = vendor.replace('-',' ')
                        vendor = vendor.replace('_',' ')
                        product = product.replace('-',' ')
                        product = product.replace('_',' ')
                        vendor_product = vendor + " " + product
                        vendor_product_version = vendor + " " + product + " " + version
                        vendor_identity = vendor
                        # Create the identity of the vendor
                        if(len(vendor) < 2):
                            vendor_identity = vendor + " "
                        vendor_send = author_send = self.helper.api.identity.create(
                            type='Organization',
                            name=vendor_identity,
                            description='',
                            update=False,
                        )
                        self.helper.log_info('Vendor ' + vendor_send["id"] + " created")
                        # Create the infrastructure
                        infrastructure_send = self.helper.api.infrastructure.create(
                            name=title,
                            description="The CPE of |" + title + "| is |" + cpe23 + "|.",
                            created_by_ref=author_send["standard_id"],
                            infrastructure_types='undefined',
                            aliases = cpe23,
                            confidence=int(self.confidence_level),
                            x_opencti_cpe_cpe23=cpe23,
                            x_opencti_cpe_vendor=vendor,
                            x_opencti_cpe_product=vendor_product,
                            x_opencti_cpe_version=vendor_product_version,
                        )
                        self.helper.log_info('Infrastructure ' + infrastructure_send["id"] + " created")
                        self.helper.api.stix_core_relationship.create(
                            fromId=infrastructure_send["id"],
                            toId=vendor_send["id"],
                            relationship_type="related-to",
                            description=vendor_send["id"] + " owns " + infrastructure_send["id"],
                            confidence=int(self.confidence_level),
                            update=True,
                        )
                        self.helper.log_info('Relation between ' + vendor_send["id"] + " + " + infrastructure_send["id"] + " created")
                        if cpe.find('{http://cpe.mitre.org/dictionary/2.0}references'):
                            # Get the references
                            references = cpe.find('{http://cpe.mitre.org/dictionary/2.0}references')
                            for reference in references.iter():
                                if(reference.tag == '{http://cpe.mitre.org/dictionary/2.0}reference'):
                                    external_reference = self.helper.api.external_reference.create(
                                        source_name=reference.text,
                                        url=reference.get('href'),
                                    )
                                    self.helper.api.stix_domain_object.add_external_reference(
                                        id=infrastructure_send["id"],
                                        external_reference_id=external_reference["id"],
                                    )
            xml_file.close()
            # Remove files
            self.delete_files()
        except Exception as e:
            print(traceback.format_exc())
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
                (timestamp - last_run) > ((int(self.cpe_interval) - 1) * 60 * 60 *24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "CPE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.convert_and_send(self.cpe_nvd_data_feed, work_id)
               
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
        self.helper.log_info("Fetching CPE knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        cpeConnector = Cpe()
        cpeConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
