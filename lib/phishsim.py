from re import search
# from ldap import initialize, SCOPE_SUBTREE
from requests import get


class GetConfig:
    """A configuration class for PhishSim integration"""
    def __init__(self, file_location):
        self.fl = file_location

    def GetToken(self):
        """Gets an API key from the config file"""
        # Note to self: quit being lazy and write a function to get the
        # API key from an encrypted file.
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            t_rgx = search(r'(^API_Key = )(\w+.+)', line)
            if t_rgx:
                return t_rgx.group(2).strip()
        config_file.close()


class PhishSimUser:
    """A class for PhishSim learners"""
    def __init__(self, e_addr):
        self.fname = str()
        self.lname = str()
        self.lid = str()
        self.email = e_addr
        self.phish_dates = []
        self.entered_data_dates = []
        self.phish_cnt = 0
        self.entr_data_cnt = 0

    def GetLearnerID(self, api_key):
        url = 'https://securityiq.infosecinstitute.com/api/v1/learners'
        token = api_key
        headers = {'Accept': 'application/json',
                   'Authorization': 'Bearer ' + token}
        request = url + '?' + 'email=' + self.email
        response = get(request, headers=headers)
        data = response.json().get('data')[0]
        self.lid = data.get('id')

    def GetLTE(self, api_key):
        url = ('https://securityiq.infosecinstitute.com/api/v1/learners/' +
               self.lid + '/timeline-events')
        token = api_key
        headers = {'Accept': 'application/json',
                   'Authorization': 'Bearer' + token}
        response = get(url, headers=headers)
        data = response.json()
        for element in data.get('data'):
            if element.get('type') == 'phished-learner':
                self.phish_cnt = self.phish_cnt + 1
                self.phish_dates.append(element.get('timestamp'))
            elif element.get('type') == 'entered-data':
                self.entr_data_cnt = self.entr_data_cnt + 1
                self.entered_data_dates.append(element.get('timestamp'))
