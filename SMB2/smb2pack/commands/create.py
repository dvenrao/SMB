from .. import smb2
from .. import constants
import string

class SMBCreate_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x39'),
        ('SecurityFlags','<B=0x0'),
        ('RequestedOplockLevel','<B'),
        ('ImpersonationLevel','<I'),
        ('SmbCreateFlags','<Q=0x0'),
        ('Reserved','<Q=0x0'),
        ('DesiredAccess','<I=0x0'),
        ('FileAttributes','<I=0x0'),
        ('ShareAccess','<I=0x0'),
        ('CreateDisposition','<I=0x0'),
        ('CreateOptions','<I=0x0'),
        ('NameOffset','<H=0x0'),
        ('NameLength','<H=0x0'),
        ('CreateContextsOffset','<I=0x0'),
        ('CreateContextsLength','<I=0x0'),
    )
class SMBCreate_Data(smb2.SMBCommand_Parameters):
    structure = (
#        ('FileName','z'),
#        ('Path','z'),
        ('filename','z=""'),
        ('ContextPadding','B=0x0'),
        ('ContextEXTA',':'),
        ('ContextSECD',':'),
        ('ContextDHNQ',':'),
        ('ContextDHNC',':'),
        ('ContextALSI',':'),
        ('ContextMXAC',':'),
        ('ContextTWRP',':'),
        ('ContextQFID',':'),
    )
class SMBCreate_ContextDHNQ(smb2.Structure):
    structure = (
        ('Next','<I=0x28'),
        ('NameOffset','<H=0x10'),
        ('NameLength','<H=0x4'),
        ('Reserved','<H=0x0'),
        ('DataOffset','<H=0x18'),
        ('DataLength','<I=0x10'),
        ('Name','<4s'),
        ('DataPadding','<I=0x0'),
        ('BinarylargeObject','<16s=""')
    )
class SMBCreate_ContextMXAC(smb2.Structure):
    structure = (
        ('Next','<I=0x18'),
        ('NameOffset','<H=0x10'),
        ('NameLength','<H=0x4'),
        ('Reserved','<H=0x0'),
        ('DataOffset','<H=0x18'),
        ('DataLength','<I=0x0'),
        ('Name','<4s'),
        ('DataPadding','<I=0x0'),
    )
class SMBCreate_ContextQFID(smb2.Structure):
    structure = (
        ('Next','<I=0x0'),
        ('NameOffset','<H=0x10'),
        ('NameLength','<H=0x4'),
        ('Reserved','<H=0x0'),
        ('DataOffset','<H=0x18'),
        ('DataLength','<I=0x0'),
        ('Name','<4s'),
        ('DataPadding','<I=0x0'),
    )
class SMBCreateResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('OplockLevel','<B'),
        ('Reserved','<B'),
        ('CreateAction','<I'),
        ('CreationTime','<Q'),
        ('LastAccessTime','<Q'),
        ('LastWriteTime','<Q'),
        ('ChangeTime','<Q'),
        ('AllocationSize','<Q'),
        ('EndofFile','<Q'),
        ('FileAttributes','<I'),
        ('Reserved2','<I'),
        ('FileId','<16s'),
        ('CreateContextsOffset','<I'),
        ('CreateContextsLength','<I'),
        ('Buffer','*:'),
    )


def create_Extend_Request_Structure(Create, filename, createflags, accessmask,
                                fileattr,sharemode,disposition,createoptions,
                                impersonation, security_flags, *create_params):
        Smb2Constants = constants.smb2Constants()
        print filename, createflags, accessmask,fileattr,sharemode,disposition,createoptions,impersonation, security_flags 
        Create['Parameters'] = SMBCreate_Parameters()
        Create['Data'] = SMBCreate_Data()

        Create['Parameters']['RequestedOplockLevel']    = createflags      
        Create['Parameters']['ImpersonationLevel']      = impersonation    
        Create['Parameters']['DesiredAccess']           = accessmask                 
        Create['Parameters']['FileAttributes']          = fileattr         
        Create['Parameters']['ShareAccess']             = sharemode        
        Create['Parameters']['CreateDisposition']       = disposition      
        Create['Parameters']['CreateOptions']           = createoptions    
        filename = filename.encode('utf-16-le')
        Payload_start = len(Create['Parameters']) + 64 #- (len(filename))/2 - 8# + 2
        Create['Parameters']['NameLength']              = len(filename)
        Create['Parameters']['NameOffset']              = Payload_start
        Payload_start += len(filename)
        CreateContextsLength                            = 0
#        Create['Parameters']['CreateContextsLength']    = 88#len(Create['Data']) - len(filename)
        Create['Parameters']['CreateContextsOffset']    = Payload_start + 2 #2-bytes is context padding 
        
        Create['Data']['filename'] = filename
        
        extafound = 0
        secdfound = 0
        dhnqfound = 0
        dhncfound = 0
        alsifound = 0
        mxacfound = 0
        twrpfound = 0
        qfidfound = 0

        cnt = 6
        while ( cnt < len(create_params)):
            tmpstr = create_params[cnt]
            tmpstr = tmpstr.strip()
#            print tmpstr
            if( string.find(tmpstr, 'DHNC') != -1):
                dhncfound = 1
                tmpstr = create_params[cnt + 1]
                tmpstr = tmpstr.strip()
                tmpstr = tmpstr.lower()
                if( string.find(tmpstr, 'fid') != -1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    dhncfid = eval(tmpstr)
                    cnt += 1
            elif( string.find(tmpstr, 'MXAC') !=-1):
                mxacfound = 1
                tmpstr = create_params[cnt + 1]
                tmpstr = tmpstr.strip()
                tmpstr = tmpstr.lower()
                if( string.find(tmpstr, 'timestamp') != -1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    mxactimestamp = eval(tmpstr)
                    cnt += 1
            elif( string.find(tmpstr, 'ALSI') !=-1):
                alsifound = 1
                cnt += 1
                tmpstr = create_params[cnt + 1]
                tmpstr = tmpstr.strip()
                tmpstr = tmpstr.lower()
                if( string.find(tmpstr, 'allocationsize') != -1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    alsiallocationsize = eval(tmpstr)
                    cnt += 1
            elif( string.find(tmpstr, 'TWRP') !=-1):
                twrpfound = 1
                cnt += 1
                tmpstr = create_params[cnt + 1]
                tmpstr = tmpstr.strip()
                tmpstr = tmpstr.lower()
                if( string.find(tmpstr, 'timestamp') != -1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    timestamp = eval(tmpstr)
                    cnt += 1
            elif( string.find(tmpstr, 'EXTA') !=-1):
                extafound = 1
            elif( string.find(tmpstr, 'SECD') !=-1):
                secdfound = 1
            elif( string.find(tmpstr, 'DHNQ') !=-1):
                dhnqfound = 1
            elif( string.find(tmpstr, 'QFID') !=-1):
                qfidfound = 1
            cnt += 1
        
        Create['Data']['ContextEXTA'] = ""
        Create['Data']['ContextSECD'] = ""
        Create['Data']['ContextDHNQ'] = ""
        Create['Data']['ContextDHNC'] = ""
        Create['Data']['ContextALSI'] = ""
        Create['Data']['ContextMXAC'] = ""
        Create['Data']['ContextTWRP'] = ""
        Create['Data']['ContextQFID'] = ""
        
        if (extafound == 1):
            CreateContextEXTA = SMBCreate_ContextMXAC()#SMBCreate_ContextEXTA()
            CreateContextEXTA['Name'] = "ExtA"
            Create['Data']['ContextEXTA'] = CreateContextEXTA
            CreateContextsLength += len(Create['Data']['ContextEXTA'])
        if (secdfound == 1):
            CreateContextSECD = SMBCreate_ContextMXAC()#SMBCreate_ContextSECD()
            CreateContextSECD['Name'] = "SecD"
            Create['Data']['ContextSECD'] = CreateContextSECD
            CreateContextsLength += len(Create['Data']['ContextSECD'])
        if (dhnqfound == 1):
            CreateContextDHNQ = SMBCreate_ContextDHNQ()
            CreateContextDHNQ['Name'] = "DHnQ"
            Create['Data']['ContextDHNQ'] = CreateContextDHNQ
            CreateContextsLength += len(Create['Data']['ContextDHNQ'])
        if (dhncfound == 1):
            CreateContextDHNC = SMBCreate_ContextDHNC()
            CreateContextDHNC['Name'] = "DHnC"
            Create['Data']['ContextDHNC'] = CreateContextDHNC
            CreateContextsLength += len(Create['Data']['ContextDHNC'])
        if (alsifound == 1):
            CreateContextALSI = SMBCreate_ContextALSI()
            CreateContextALSI['Name'] = "ALSI"
            Create['Data']['ContextALSI'] = CreateContextALSI
            CreateContextsLength += len(Create['Data']['ContextALSI'])
        if (mxacfound == 1):
            CreateContextMXAC = SMBCreate_ContextMXAC()
            CreateContextMXAC['Name'] = "MXAC"
            Create['Data']['ContextMXAC'] = CreateContextMXAC
            CreateContextsLength += len(Create['Data']['ContextMXAC'])
        if (twrpfound == 1):
            CreateContextTWRP = SMBCreate_ContextTWRP()
            CreateContextTWRP['Name'] = "TWrp"
            Create['Data']['ContextTWRP'] = CreateContextTWRP
            CreateContextsLength += len(Create['Data']['ContextTWRP'])
        if (qfidfound == 1):
            CreateContextQFID = SMBCreate_ContextQFID()
            CreateContextQFID['Name'] = "QFid"
            Create['Data']['ContextQFID'] = CreateContextQFID
            CreateContextsLength += len(Create['Data']['ContextQFID'])        
            
      
#        CreateContextDHNQ = SMBCreate_ContextDHNQ()
#        CreateContextDHNQ['Name'] = "DHnQ"
#        CreateContextMXAC = SMBCreate_ContextMXAC()
#        CreateContextMXAC['Name'] = "MxAc"
#        CreateContextQFID = SMBCreate_ContextQFID()
#        CreateContextQFID['Name'] = "QFid"
#        
#        
#        Create['Data']['ContextDHNQ'] = CreateContextDHNQ
#        Create['Data']['ContextMXAC'] = CreateContextMXAC
#        Create['Data']['ContextQFID'] = CreateContextQFID
#        Create['Parameters']['CreateContextsLength'] = len(Create['Data']['ContextDHNQ']) + \
#                         len(Create['Data']['ContextMXAC']) + len(Create['Data']['ContextQFID'])
                         
        Create['Parameters']['CreateContextsLength'] = CreateContextsLength 

        return Create


def create_Response_Structure(createResponse):
        Smb2Constants = constants.smb2Constants()
        createParameters = SMBCreateResponse_Parameters(createResponse['Parameters'])
        fid = createParameters['FileId']
        filesize = createParameters['EndofFile']
        return fid,filesize

def create_Request_Structure(Create, *create_params):
        amfound = 0
        fattrfound =0
        smfound = 0
        cofound = 0
        dispfound = 0
        oplockfound =0
        impersonationfound = 0
        securtiyfound = 0

        filename = create_params[0]
        cnt = 1
        while ( cnt < len(create_params)):
            tmpstr = create_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'oplock') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                createflags = eval(tmpstr)
                oplockfound = 1
            elif( string.find(tmpstr, 'accessmask') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                accessmask = eval(tmpstr)
                amfound = 1
            elif( string.find(tmpstr, 'fileattr') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                fileattr = eval(tmpstr)
                fattrfound = 1
            elif( string.find(tmpstr, 'sharemode') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                sharemode = eval(tmpstr)
                smfound = 1
            elif( string.find(tmpstr, 'disposition') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                disposition = eval(tmpstr)
                dispfound = 1
            elif( string.find(tmpstr, 'createoptions') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                createoptions = eval(tmpstr)
                cofound = 1
            elif( string.find(tmpstr, 'impersonation') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                impersonation = eval(tmpstr)
                impersonationfound = 1
            elif( string.find(tmpstr, 'securityflags') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                security_flags = eval(tmpstr)
                securityfound = 1
            cnt += 1

        if (oplockfound == 0):
            createflags = 0x00
        if (fattrfound== 0):
            fileattr = 128
        if ( smfound == 0):
            sharemode = 3
        if ( cofound == 0):
            createoptions = 2112
        if ( dispfound == 0):
            disposition = 3
        if ( amfound == 0):
            accessmask = 7
        if ( impersonationfound==0):
            impersonation = 2
        if (securtiyfound==0):
            security_flags = 3 #eval(create_params[8])

        Create1 = create_Extend_Request_Structure(Create, filename, createflags, accessmask,
                                fileattr,sharemode,disposition,createoptions,
                                impersonation, security_flags, *create_params)
        return Create1