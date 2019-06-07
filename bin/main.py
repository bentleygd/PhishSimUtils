#!/usr/bin/python
from sys import path
path.insert(0, '../lib')
import coreutils
import phishsim


# Setting configuration file.
ps_config = coreutils.GetConfig('../PhishSim.cnf')
# Setting the results file.
r_file = open(ps_config.ResultsFile(), 'w')
# Setting the not enrolled file.
ne_file = open(ps_config.NotEnrolled(), 'w')
# Gettting info for decrypting API token
token_location = ps_config.Token()
gpghome = ps_config.GPGHome()
gpg_pass = str(open(ps_config.GPGPass(), 'r').read()).strip('\n')
api_key = str(coreutils.DecryptGPG(token_location, gpghome, gpg_pass)
              ).strip('\n')

# Setting LDAP Info
l_url = ps_config.LDAP_URL()
l_bdn = ps_config.LDAP_BDN()
l_pass = str(coreutils.DecryptGPG(ps_config.LDAP_Pass(), gpghome, gpg_pass)
             ).strip('\n')
l_ous = ps_config.LDAPSearchOU()

# Getting Mail Users from AD
mail_users = phishsim.GetADMailUsers(l_url, l_bdn, l_pass, l_ous)

# Building PhishSim Learner File
for user in mail_users:
    learner = phishsim.PhishSimUser(user.strip('\n'))
    learner.GetLearnerID(api_key)
    if not learner.lid == 'not_enrolled':
        learner.GetLTE(api_key)
        f_names = ['First Name', 'Last Name', 'Email', 'Learner_ID']
        user_d = {'First Name': learner.fname,
                  'Last Name': learner.lname,
                  'Email': learner.email,
                  'Learner_ID': learner.lid}
        phishsim.PhishSimCSV(f_names, r_file, user_d)
    else:
        ne_file.write(user + '\n')
    break

r_file.close()
ne_file.close()
