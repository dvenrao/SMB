import sys
import string
import ConfigParser


config = ConfigParser.ConfigParser()
#self.const = constants.smb2Constants()
config.read('smb2pack/smb2setup.cfg')
remoteIP = config.get('setup', 'cifsserverip')
smbport = config.get('setup', 'port')
username =  config.get('setup', 'username')
password = config.get('setup', 'password')
share = config.get('setup', 'sharename')