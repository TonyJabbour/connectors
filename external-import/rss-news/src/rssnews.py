# coding: utf-8

import time
from datetime import datetime, timedelta
import stix2
import yaml
import os
import ast
import feedparser
import snscrape.modules.twitter as sntwitter
import re
from pycti import OpenCTIConnectorHelper, OpenCTIApiWork, get_config_variable, Identity, Note


class News:
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
        self.news_interval = get_config_variable(
            "FETCHING_INTERVAL", ["news", "interval"], config, True
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
        self.data_rss = ast.literal_eval(get_config_variable(
            "LIST_DATA_RSS",
            ["news", "list_data_rss"],
            config,
        ))
        self.data_twitter = ast.literal_eval(get_config_variable(
            "LIST_TWITTER_USER",
            ["news", "list_twitter_user"],
            config,
        ))

    def get_interval(self):
        return int(self.news_interval) * 60

    def convert_and_send_twitter(self, username, work_id):
        user = 'Twitter / @' + username
        list_already_present = self.helper.api.note.list(getAll=True,customAttributes="authors attribute_abstract")
        nombre_max = 200
        for i in list_already:
            if(user in i['authors']):
                nombre_max = 15
                break
        try:
            bundle_to_send = []
            # Downloading zip file
            self.helper.log_info("Requesting the feed from " + username)
            # Create the identity of the author
            self.helper.log_info("Creating the author " + username)
            author = stix2.Identity(
                id=Identity.generate_id(user, "organization"),
                name=user,
                identity_class="organization",
            )
            bundle_to_send.append(author)
            self.helper.log_info("Processing the feed...")
            try:
                for i,tweet in enumerate(sntwitter.TwitterUserScraper(username='{}'.format(username)).get_items()):
                    if(i == nombre_max):
                        break
                    date = tweet.date
                    content_with = tweet.renderedContent.split(' ')
                    if(username == 'tehtris' and 'tehtris.com/fr/blog/' not in tweet.renderedContent):
                        continue
                    index = 0
                    for i in content_with:
                        if('…' in i):
                            content_with.pop(index)
                            index += 1
                        else:
                            index += 1
                    content = ' '.join(content_with)
                    url = tweet.url
                    external_reference = stix2.ExternalReference(
                        source_name=username, url=url
                    )
                    external_references = [external_reference]
                    flag = False
                    for i in list_already_present:
                        if(content == i["attribute_abstract"]):
                            flag = True
                            break
                    if(flag == False):
                        note = stix2.Note(
                            id=Note.generate_id(),
                            abstract=content,
                            created=date,
                            content=content,
                            authors=author["name"],
                            external_references=external_references,
                            object_refs=author,
                        )
                        bundle_to_send.append(note)
            except Exception as e:
                self.helper.log_error('Error : ' + str(e))
                
            # Send the bundle
            bundle = stix2.Bundle(bundle_to_send, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                bundle_json,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
            self.worker.wait_for_work_to_finish(work_id)
            time.sleep(10)
        except Exception as e:
            self.helper.log_error(str(e))
            time.sleep(60)


    def convert_and_send_rss(self, data_rss, work_id):
        list_already_note = self.helper.api.note.list(getAll=True,customAttributes="attribute_abstract")
        try:
            bundle_to_send = []
            # Downloading zip file
            self.helper.log_info("Requesting the feed " + data_rss[0])
            # Create the identity of the author
            self.helper.log_info("Creating the author " + data_rss[1])
            author = stix2.Identity(
                id=Identity.generate_id(data_rss[1], "organization"),
                name=data_rss[1],
                identity_class="organization",
            )
            bundle_to_send.append(author)
            self.helper.log_info("Processing the feed...")
            feeder = feedparser.parse(data_rss[0])
            index = 0
            while True:
                try:
                    abstract = feeder.entries[index]['title']
                    if(abstract == ""):
                        abstract = "---"
                    link = feeder.entries[index]['link']
                    if(link == ""):
                        link = "---"
                    external_reference = stix2.ExternalReference(
                        source_name=data_rss[1], url=link
                    )
                    external_references = [external_reference]
                    try:
                        content = feeder.entries[index]['summary']
                        if(content == ""):
                            content = abstract
                    except KeyError:
                        content = abstract
                    created = datetime.strptime(feeder.entries[index]['updated'], data_rss[2])
                    if(re.compile('^[0-9]*$').match(data_rss[-1][-4:-2])):
                        created = created - timedelta(hours=int(data_rss[2][-4:-2]))
                    flag = False
                    for i in list_already_note:
                        if(abstract == i["attribute_abstract"]):
                            flag = True
                            break
                    if(flag == False):
                        note = stix2.Note(
                                id=Note.generate_id(),
                                abstract=abstract,
                                created=created,
                                content=content,
                                authors=author["name"],
                                external_references=external_references,
                                object_refs=author
                            )
                        bundle_to_send.append(note)
                    index += 1
                except:
                    break
            # Send the bundle
            bundle = stix2.Bundle(bundle_to_send, allow_custom=True)
            bundle_json = bundle.serialize()
            self.helper.send_stix2_bundle(
                bundle_json,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
            self.worker.wait_for_work_to_finish(work_id)
        except Exception as e:
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
            # If the last_run is more than interval-1 minute
            if last_run is None or (
                (timestamp - last_run) > ((int(self.news_interval) - 1) * 60)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "RSS & News run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                index_process = 0
                for index_process in range(0,len(self.data_rss)):
                    self.convert_and_send_rss(self.data_rss[index_process], work_id)
                index_process = 0
                for index_process in range(0,len(self.data_twitter)):
                    self.convert_and_send_twitter(self.data_twitter[index_process], work_id)

                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60, 2))
                    + " minutes"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60, 2))
                    + " minutes"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching News knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        newsConnector = News()
        newsConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
