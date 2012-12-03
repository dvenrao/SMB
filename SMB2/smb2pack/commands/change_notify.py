from .. import smb2
from .. import constants
import string

class SMBChange_notify_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x21'),
        ('Flags','<H=0x0'),
        ('OutputBufferLength','<I=0x0'),
        ('FileId','<16s=""'),
        ('CompletionFilter','<I=0x0'),
        ('Reserved','<I=0x0'),
    )
class SMBChange_notify_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBChange_notifyResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('OutputBufferOffset','<H'),
        ('OutputBufferLength','<I'),
        ('Buffer',':'),
    )


def change_notify_Extend_Request_Structure(Change_notify, fileId, offset, data):
        Smb2Constants = constants.smb2Constants()
        
        Change_notify['Parameters'] = SMBChange_notify_Parameters()
        Change_notify['Data'] = SMBChange_notify_Data()

        Change_notify['Parameters']['Flags']                = 0     
        Change_notify['Parameters']['OutputBufferLength']   = 0    
        Change_notify['Parameters']['FileId']               = fileId 
        Change_notify['Parameters']['CompletionFilter']     = Smb2Constants.FILE_NOTIFY_CHANGE_FILE_NAME                  
                                                                         
        Change_notify['Data']['data'] = data
        return Change_notify

def change_notify_Response_Structure(change_notifyResponse):
        Smb2Constants = constants.smb2Constants()
        #change_notifyParameters = SMBChange_notifyResponse_Parameters(change_notifyResponse['Parameters'])
        #data = change_notifyParameters['Buffer']
        return 1

def change_notify_Request_Structure(Change_notify, fileId, *change_notify_params):
        offsetfound = 0
        datafound = 0
        cnt = 0
        while ( cnt < len(change_notify_params)):
            tmpstr = change_notify_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'offset') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                offset = eval(tmpstr)
                offsetfound = 1
            elif( string.find(tmpstr, 'data') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                data = tmpstr
                datafound = 1
                #print data
            cnt += 1

        if (offsetfound == 0):
            offset = 0x0
        if (datafound == 0):
            data = 0x0

        Change_notify1 = change_notify_Extend_Request_Structure(Change_notify, fileId, offset, data)
        return Change_notify1