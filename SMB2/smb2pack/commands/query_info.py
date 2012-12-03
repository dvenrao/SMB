from .. import smb2
from .. import constants
import string

class SMBQuery_info_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x29'),
        ('InfoType','<B=0x0'),
        ('FileInfoClass','<B=0x0'),
        ('OutputBufferLength','<I=0x21'),
        ('InputBufferOffset','<H=0x0'),
        ('Reserved','<H=0x0'),
        ('InputBufferLength','<I=0x21'),
        ('AdditionalInformation','<I=0x0'),
        ('Flags','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBQuery_info_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBQuery_infoResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('OutputBufferOffset','<H'),
        ('OutputBufferLength','<I'),
        ('Buffer',':'),
    )


def query_info_Extend_Request_Structure(Query_info, fileId, infotype, fileinfoclass):
        Smb2Constants = constants.smb2Constants()
        Query_info['Parameters'] = SMBQuery_info_Parameters()
        Query_info['Data'] = SMBQuery_info_Data()

        Query_info['Parameters']['InfoType']              = infotype
        Query_info['Parameters']['FileInfoClass']         = fileinfoclass  
        Query_info['Parameters']['OutputBufferLength']    = 65000
        Query_info['Parameters']['InputBufferOffset']     = 0
        Query_info['Parameters']['AdditionalInformation'] = 0
        Query_info['Parameters']['Flags']                 = 0
        Query_info['Parameters']['FileId']               = fileId
                                                                         
        Query_info['Data']['data'] = ""
        return Query_info

def query_info_Response_Structure(query_infoResponse):
        Smb2Constants = constants.smb2Constants()
        #query_infoParameters = SMBQuery_infoResponse_Parameters(query_infoResponse['Parameters'])
        #data = query_infoParameters['Buffer']
        return 1

def query_info_Request_Structure(Query_info, fileId, *query_info_params):
        infotypefound = 0
        fileinfoclassfound = 0
        cnt = 0
        while ( cnt < len(query_info_params)):
            tmpstr = query_info_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'infotype') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                infotype = eval(tmpstr)
                infotypefound = 1
            elif( string.find(tmpstr, 'fileinfoclass') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                fileinfoclass = eval(tmpstr)
                fileinfoclassfound = 1
                #print fileinfoclass
            cnt += 1

        if (infotypefound == 0):
            infotype = 0x0
        if (fileinfoclassfound == 0):
            fileinfoclass = 0x0

        Query_info1 = query_info_Extend_Request_Structure(Query_info, fileId, infotype, fileinfoclass)
        return Query_info1