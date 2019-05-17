#!/usr/bin/python
from smptlib import SMTP
from email.mime.text import MIMEText
from re import search
from gnupg import GPG


class GetConfig:
    """A configuration class, customized for PhishSim integration"""
    def __init__(self, file_location):
        self.fl = file_location

    def Token(self):
        """Gets an API key location from the config file."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            t_rgx = search(r'(^API_Key = )(.+)', line)
            if t_rgx:
                return t_rgx.group(2).strip()
        config_file.close()

    def GPGHome(self):
        """Gets gpg's home dir from config file."""
        config_file = open(self.fl, 'r+b')
        for line in config_file:
            gpg_rgx = search(r'(^GNUPGHOME = )(.+)', line)
            if gpg_rgx:
                return gpg_rgx.group(2).strip()
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


def MailSend(mail_sender, mail_recipients, mail_server, mail_body):
    """Simple function to send mail."""
    msg = MIMEText(mail_body)
    msg['Subject'] = 'MSFT IP Scrape'
    msg['From'] = mail_sender
    msg['To'] = mail_recipients
    s = SMTP(gethostbyname(mail_server), '25')
    s.sendmail(mail_sender, mail_recipients, msg.as_string())


def DecryptGPG(cipher_file, gpghome, p_phrase)
    """Simple decrypt."""
    cipher_data = str(open(cipher_file, 'r').read())
    g = GPG(gpghome)
    clear_data = g.decrypt(cipher_data, p_phrase).strip('\n')
    return clear_data
