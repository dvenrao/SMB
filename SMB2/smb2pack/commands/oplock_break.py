from .. import smb2
from .. import constants
import string

class SMBOplock_break_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x18'),
        ('OplockLevel','<B=0x0'),
        ('Reserved','<B=0x0'),
        ('Reserved2','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBOplock_Lease_Break_Notification(smb2.Structure):
    structure = (
        ('StructureSize','<H=0x2c'),
        ('Reserved','<H=0x0'),
        ('Flags','<I=0x0'),
        ('LeaseKey','<16s=""'),
        ('CurrentLeaseState','<16s=""'),
        ('NewLeaseState','<I=0x0'),
        ('BreakReason','<I=0x0'),
        ('AccessMaskHint','<I=0x0'),
        ('ShareMaskHint','<I=0x0'),
    )
class SMBOplock_break_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBOplock_breakResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('OplockLevel','<B'),
        ('Reserved','<B'),
        ('Reserved2','<H'),
        ('FileId','<16s=""'),
        ('Buffer',':'),
    )


def oplock_break_Extend_Request_Structure(Oplock_break, fileId, offset, data):
        Smb2Constants = constants.smb2Constants()
        
        Oplock_break['Parameters'] = SMBOplock_break_Parameters()
        Oplock_break['Data'] = SMBOplock_break_Data()

        Oplock_break['Parameters']['OplockLevel']            = 0x0
        Oplock_break['Parameters']['FileId ']               = fileId
                                                                         
        Oplock_break['Data']['data'] = ""
        return Oplock_break

def oplock_break_Response_Structure(oplock_breakResponse):
        Smb2Constants = constants.smb2Constants()
        #oplock_breakParameters = SMBOplock_breakResponse_Parameters(oplock_breakResponse['Parameters'])
        #data = oplock_breakParameters['Buffer']
        return 1

def oplock_break_Request_Structure(Oplock_break, fileId, *oplock_break_params):
        offsetfound = 0
        datafound = 0
        cnt = 0
        while ( cnt < len(oplock_break_params)):
            tmpstr = oplock_break_params[cnt]
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

        Oplock_break1 = oplock_break_Extend_Request_Structure(Oplock_break, fileId, offset, data)
        return Oplock_break1