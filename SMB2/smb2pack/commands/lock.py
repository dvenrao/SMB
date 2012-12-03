from .. import smb2
from .. import constants
import string

class SMBLock_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x30'),
        ('LockCount','<H=0x0'),
        ('LockSequence','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBCreate_Lock_Element(smb2.Structure):
    structure = (
        ('Offset','<Q=0x0'),
        ('Length','<Q=0x0'),
        ('Flags','<I=0x0'),
        ('Reserved','<I=0x0'),
    )
class SMBLock_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
    )
class SMBLockResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('Reserved','<H'),
        ('Buffer',':'),
    )


def lock_Extend_Request_Structure(Lock, fileId, offset, data):
        Smb2Constants = constants.smb2Constants()
        
        Lock['Parameters'] = SMBLock_Parameters()
        Lock['Data'] = SMBLock_Data()

        Lock['Parameters']['LockCount']            = 1
        Lock['Parameters']['FileId ']               = fileId
                                                                         
        Lock['Data']['data'] = ""
        return Lock

def lock_Response_Structure(lockResponse):
        Smb2Constants = constants.smb2Constants()
        #lockParameters = SMBLockResponse_Parameters(lockResponse['Parameters'])
        #data = lockParameters['Buffer']
        return 1

def lock_Request_Structure(Lock, fileId, *lock_params):
        offsetfound = 0
        datafound = 0
        cnt = 0
        while ( cnt < len(lock_params)):
            tmpstr = lock_params[cnt]
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

        Lock1 = lock_Extend_Request_Structure(Lock, fileId, offset, data)
        return Lock1