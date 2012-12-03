from .. import smb2
from .. import constants
import string

class SMBIoctl_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x39'),
        ('Reserved','<H=0x0'),
        ('CtlCode','<I=0x0'),
        ('FileId','<16s=""'),
        ('InputOffset','<I=0x0'),
        ('InputCount','<I=0x0'),
        ('MaxInputResponse','<I=0x0'),
        ('OutputOffset','<I=0x0'),
        ('OutputCount','<I=0x0'),
        ('MaxOutputResponse','<I=0x0'),
        ('Flags','<I=0x0'),
        ('Reserved2','<I=0x0'),
    )
class SMBIoctl_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBIoctlResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('Reserved','<H'),
        ('CtlCode','<I'),
        ('FileId','<16s=""'),
        ('InputOffset','<I='),
        ('InputCount','<I='),
        ('OutputOffset','<I='),
        ('OutputCount','<I='),
        ('Flags','<I='),
        ('Flags','<I='),
        ('Reserved2','<I='),
        ('Buffer',':'),
    )


def ioctl_Extend_Request_Structure(Ioctl, fileId, offset, data):
        Smb2Constants = constants.smb2Constants()
        
        Ioctl['Parameters'] = SMBIoctl_Parameters()
        Ioctl['Data'] = SMBIoctl_Data()

        Ioctl['Parameters']['InfCtlCode']       = Smb2Constants.FSCTL_DFS_GET_REFERRALS   
        Ioctl['Parameters']['FileId ']          = fileId
                                                                         
        Ioctl['Data']['data'] = ""
        return Ioctl

def ioctl_Response_Structure(ioctlResponse):
        Smb2Constants = constants.smb2Constants()
        #ioctlParameters = SMBIoctlResponse_Parameters(ioctlResponse['Parameters'])
        #data = ioctlParameters['Buffer']
        return 1

def ioctl_Request_Structure(Ioctl, fileId, *ioctl_params):
        offsetfound = 0
        datafound = 0
        cnt = 0
        while ( cnt < len(ioctl_params)):
            tmpstr = ioctl_params[cnt]
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

        Ioctl1 = ioctl_Extend_Request_Structure(Ioctl, fileId, offset, data)
        return Ioctl1