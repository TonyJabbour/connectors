import os
import re
import yaml
from pycti import OpenCTIConnectorHelper
import subprocess
from datetime import datetime
import json

class Twitter:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        
    def enrichCVE(self, cve):
        try:
            # Top tweet
            min_faves = 5000
            while(True):
                output = subprocess.check_output("snscrape --jsonl --max-results 3 twitter-search \"{} min_faves:{}\" --top".format(cve,min_faves), shell=True).decode('UTF-8')
                if(output.count('{"_type": "snscrape.modules.twitter.Tweet"') == 3):
                    break
                else:
                    if(min_faves <= 100):
                        min_faves = min_faves - 10
                    elif(min_faves <= 1000):
                        min_faves = min_faves - 100
                    else:
                        min_faves = min_faves - 1000
            toptweet = output.replace('true','"True"')
            toptweet = toptweet.replace('null','"None"')
            # Genetating error because " parsed in value => error
            toptweet = toptweet.replace('<a href="https://mobile.twitter.com" rel="nofollow">Twitter Web App</a>',"<a href='https://mobile.twitter.com' rel='nofollow'>Twitter Web App</a>")
            toptweet_list = []
            toptweet_list = toptweet.split('\n')[:-1]
            with open('/opt/generated/{}.txt'.format(cve),'w') as file:
                for i in toptweet_list:
                    after = json.loads(i)
                    url = after['url']
                    date = datetime.strptime(after['date'],'%Y-%m-%dT%H:%M:%S+00:00')
                    date = date.strftime('%d/%m/%Y %H:%M:%S')
                    content = after['content']
                    username = after['user']['username']
                    displayname = after['user']['displayname']
                    user = username + ' / @' + displayname
                    followers_count = after['user']['followersCount']
                    retweet_count = after['retweetCount']
                    like_count = after['likeCount'] 
                    string_result = {'source': 'Twitter', 'type_twitter': 'Top tweet', 'number_cve': cve, 'date': str(date), 'content': content, 'url': url,'user': user,'followers_count': str(followers_count),'retweet_count': str(retweet_count),'like_count': str(like_count)}
                    file.write(str(string_result) + '\n')
            file.close()
        except Exception as e:
            print(str({'source': 'Twitter', 'number_cve': cve, 'content': '[error] ' + str(e)}))

    def _process_message(self, data):
        cve = data['entity_id']
        if not (re.match('^CVE-\d{4}-\d{3,5}$', cve)):
            with open('/opt/generated/{}.txt'.format(cve),'w') as file:
                file.write(str({'source': 'Twitter', 'number_cve': cve, 'content': '[error] Wrong CVE format !'}))
            file.close()
            return
        ##################### Twitter #####################
        if(subprocess.check_output("snscrape --max-results 1 twitter-search {}".format(cve), shell=True).decode('UTF-8') == ''):
            with open('/opt/generated/{}.txt'.format(cve),'w') as file:
                file.write(str({'source': 'Twitter', 'number_cve': cve, 'content': '[error] No result !'}))
            file.close()
            return
        else:
            self.enrichCVE(cve)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    Twitter = Twitter()
    Twitter.start()
