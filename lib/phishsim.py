from requests import get
from requests.exceptions import ConnectionError
from ldap import initialize, SCOPE_SUBTREE
from csv import DictWriter


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
        self.l_data = {'First Name':self.fname,
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
        try:
            response = get(request, headers=headers)
        except ConnectionError:
            print 'Unable to connect to URL'
        if len(response.json().get('data')) > 0:
            # print self.email, 'is enrolled in SecurityIQ'
            data = response.json().get('data')[0]
            self.lid = data.get('id')
            self.fname = data.get('first_name')
            self.lname = data.get('last_name')
        else:
            # print self.email, 'not enrolled in SecurityIQ.'
            self.lid = 'not_enrolled'

    def GetLTE(self, api_key):
        """Gets phished and entered data for a learner."""
        url = ('https://securityiq.infosecinstitute.com/api/v1/learners/' +
               self.lid + '/timeline-events')
        token = api_key
        headers = {'Accept': 'application/json',
                   'Authorization': 'Bearer ' + token}
        response = get(url, headers=headers)
        data = response.json()
        for element in data.get('data'):
            if element.get('type') == 'phished-learner':
                self.phish_cnt = self.phish_cnt + 1
                self.phish_dates.append(element.get('timestamp'))
            elif element.get('type') == 'entered-data':
                self.entr_data_cnt = self.entr_data_cnt + 1
                self.entered_data_dates.append(element.get('timestamp'))


def GetADMailUsers(ldap_url, bind_dn, passw, ous):
    """Retrieves email addresses from AD."""
    email_list = []
    ldap_obj = initialize(ldap_url)
    ldap_obj.simple_bind_s(bind_dn, passw)
    for ou in ous:
        user_data = (ldap_obj.search_s(ou, SCOPE_SUBTREE, 'mail=*', ['mail'],
                     attrsonly=0))
        for data in user_data:
            email_list.append(data[1].get('mail')[0].lower().strip('\n'))
    return email_list


def PhishSimCSV(field_names, f_obj, user_d):
    """Writes results to a CSV file."""
    f_names = field_names
    writer = DictWriter(f_obj, fieldnames=f_names)
    writer.writerow(user_d)
