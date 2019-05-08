from re import search


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
        config_file.close()
        return t_rgx.group(2).strip()
