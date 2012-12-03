from .. import smb2
from .. import constants
import string

class SMBWrite_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x31'),
        ('DataOffset','<H=0x70'),
        ('Length','<I=0x0'),
        ('Offset','<Q=0x0'),
        ('FileId','<16s=""'),
        ('Channel','<I=0x0'),
        ('RemainingBytes','<I=0x0'),
        ('WriteChannelInfoOffset','<H=0x0'),
        ('WriteChannelInfoLength','<H=0x0'),
        ('Flags','<I=0x0'),
    )
class SMBWrite_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBWriteResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('DataOffset','<B'),
        ('Reserved','<B'),
        ('DataLength','<I'),
        ('DataRemaining','<I'),
        ('Reserved2','<I'),
        ('Buffer',':'),
    )


def write_Extend_Request_Structure(Write, fileId, offset, data):
        Smb2Constants = constants.smb2Constants()
        
        Write['Parameters'] = SMBWrite_Parameters()
        Write['Data'] = SMBWrite_Data()

        Write['Parameters']['Length']    = len(data)      
        Write['Parameters']['Offset']      = offset    
        Write['Parameters']['FileId']      = fileId                 
                                                                         
        Write['Data']['data'] = data
        return Write

def write_Response_Structure(writeResponse):
        Smb2Constants = constants.smb2Constants()
        #writeParameters = SMBWriteResponse_Parameters(writeResponse['Parameters'])
        #data = writeParameters['Buffer']
        return 1

def write_Request_Structure(Write, fileId, *write_params):
        offsetfound = 0
        datafound = 0
        cnt = 0
        while ( cnt < len(write_params)):
            tmpstr = write_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'offset') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                offset = eval(tmpstr)
                #print offset
                offsetfound = 1
            elif( string.find(tmpstr, 'data') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                data = tmpstr
                datafound = 1
            cnt += 1

        if (offsetfound == 0):
            offset = 0x0
        if (datafound == 0):
            data = 0x0

        Write1 = write_Extend_Request_Structure(Write, fileId, offset, data)
        return Write1