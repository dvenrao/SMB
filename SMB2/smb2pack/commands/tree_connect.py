from .. import smb2
from .. import constants
import string

class SMBTree_connect_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x9'),
        ('Reserved','<H=0x0'),
        ('PathOffset','<H'),
        ('PathLength','<H'),
    )
class SMBTree_connect_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('Path',':'),
    )
class SMBTree_connectResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('ShareType','<B'),
        ('Reserved','<B'),
        ('ShareFlags','<I'),
        ('Capabilities','<I'),
        ('MaximalAccess','<I'),
    )


def tree_connect_Request_Structure(Tree_connect, path):
        Smb2Constants = constants.smb2Constants()
        
        Tree_connect['Parameters'] = SMBTree_connect_Parameters()
        Tree_connect['Data'] = SMBTree_connect_Data()

        Tree_connect['Parameters']['PathOffset'] = 64 + 8
        path = path.encode('utf-16-le')
        Tree_connect['Data']['Path'] = path
        Tree_connect['Parameters']['PathLength'] = len(path)
                                                                         
        return Tree_connect

def tree_connect_Response_Structure(tree_connectResponse):
        Smb2Constants = constants.smb2Constants()
        tree_connectParameters = SMBTree_connectResponse_Parameters(tree_connectResponse['Parameters'])
        ShareType     = tree_connectParameters['ShareType']
        ShareFlags    = tree_connectParameters['ShareFlags']
        Capabilities  = tree_connectParameters['Capabilities']
        MaximalAccess = tree_connectParameters['MaximalAccess']
        return Capabilities

