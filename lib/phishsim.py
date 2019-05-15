from re import search
from requests import get


class GetConfig:
    """A configuration class for PhishSim integration"""
    def __init__(self, file_location):
        self.fl = file_location

    def Token(self):
        """Gets an API key from the config file."""
        # Note to self: quit being lazy and write a function to get the
        # API key from an encrypted file.
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            t_rgx = search(r'(^API_Key = )(\w+.+)', line)
            if t_rgx:
                return t_rgx.group(2).strip()
        config_file.close()

    def LDAP_BDN(self):
        """Gets an LDAP Bind DN from the config file."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            bdn_rgx = search(r'(^LDAP_BDN: )(.+)', line)
            if bdn_rgx:
                return bdn_rgx.group(2).strip()
        config_file.close()

    def LDAP_URL(self):
        """Gets the LDAP URL to connect to."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            lurl_rgx = search(r'(^LDAP_URL: )(.+)', line)
            if lurl_rgx:
                return lurl_rgx.group(2).strip()
        config_file.close()

    def LDAP_Pass(self):
        """Gets the password for an LDAP connection."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            pass_rgx = search(r'(^PASS_FILE: )(.+)', line)
            if pass_rgx:
                return pass_rgx.group(2).strip()
        config_file.close()

    def LDAPSearchOU(self):
        """Gets a list of OUs to search through."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            ou_rgx = search(r'(^SEARCH_OUs: )(.+)', line)
            if ou_rgx:
                search_ou = ou_rgx.group(2).split('|')
                return search_ou
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
        self.learner_data = {'First Name':self.fname,
                             'Last Name':self.lname,
                             'Email Address':self.email,
                             'Phish Count':self.phish_cnt,
                             'Entered Data Count':self.entr_data_cnt}

    def GetLearnerID(self, api_key):
        """Gets the learner ID based on the learner email."""
        url = 'https://securityiq.infosecinstitute.com/api/v1/learners'
        token = api_key
        headers = {'Accept': 'application/json',
                   'Authorization': 'Bearer ' + token}
        request = url + '?' + 'email=' + self.email
        response = get(request, headers=headers)
        data = response.json().get('data')[0]
        self.lid = data.get('id')

    def GetLTE(self, api_key):
        """Gets phished and entered data for a learner."""
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
