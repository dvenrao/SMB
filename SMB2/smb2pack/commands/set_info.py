from .. import smb2
from .. import constants
import string

class SMBSet_info_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x21'),
        ('InfoType','<B=0x0'),
        ('FileInfoClass','<B=0x0'),
        ('BufferLength','<I=0x21'),
        ('BufferOffset','<H=0x0'),
        ('Reserved','<H=0x0'),
        ('AdditionalInformation','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBSet_info_Data(smb2.SMBCommand_Parameters):
    structure = (
        ('data',':'),
        ('FileRenameInf',':'),
    )
class SMBSet_info_FileRenameInf(smb2.Structure):
    structure = (
        ('ReplaceIfExists','<B'),
        ('Reserved','<7s=""'),
        ('RootDirectory','<Q=0x0'),
        ('FileNameLength','<I'),
        ('FileName',':'),
    )
class SMBSet_info_Dispositon(smb2.Structure):
    structure = (
        ('FileInfo','<B=0x1'),
    )
class SMBSet_info_EndOfFileInformation(smb2.Structure):
    structure = (
        ('EndOfFile','<Q=0x3453'),
    )
class SMBSet_infoResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('Buffer',':'),
    )


def set_info_Extend_Request_Structure(Set_info, fileId, infotype, fileinfoclass, *set_info_params):
        Smb2Constants = constants.smb2Constants()
        
        Set_info['Parameters'] = SMBSet_info_Parameters()
        Set_info['Data'] = SMBSet_info_Data()

        Set_info['Parameters']['InfoType']              = infotype   
        Set_info['Parameters']['FileInfoClass']         = fileinfoclass   
        Set_info['Parameters']['BufferLength']          = 0
        Set_info['Parameters']['BufferOffset']          = 0x60
        Set_info['Parameters']['AdditionalInformation'] = 0 
        Set_info['Parameters']['FileId']                = fileId   
        
        Set_info['Data']['data'] = ""
        Set_info['Data']['FileRenameInf'] = ""
        
        if (fileinfoclass == 10):
            replaceifexistsfound = 0
            filenamefound = 0
            cnt = 2
            while ( cnt < len(set_info_params)):
                tmpstr = set_info_params[cnt]
                tmpstr = tmpstr.strip()
                tmpstr = tmpstr.lower()
                if( string.find(tmpstr, 'replaceifexists') != -1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    replaceifexists = eval(tmpstr)
                    replaceifexistsfound = 1
                elif( string.find(tmpstr, 'filename') !=-1):
                    tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                    filename = tmpstr
                    filename = filename.encode('utf-16-le')
                    filenamefound = 1
                    #print filename
                cnt += 1

            if (replaceifexistsfound == 0):
                replaceifexists = 0x0
            if (filenamefound == 0):
                filename = "renamed.txt"
                filename = filename.encode('utf-16-le')
                print "file name not given so default renamed to renamed.txt"
        
            Set_info_FileRenameInf = SMBSet_info_FileRenameInf()
            Set_info_FileRenameInf['ReplaceIfExists'] = replaceifexists
            Set_info_FileRenameInf['FileName'] = filename
            Set_info_FileRenameInf['FileNameLength'] = len(filename)
            Set_info['Data']['FileRenameInf'] = Set_info_FileRenameInf
            Set_info['Parameters']['BufferLength'] = len(Set_info['Data']['FileRenameInf'])           
        
        if (fileinfoclass == 13):
            Set_info_Dispositon = SMBSet_info_Dispositon()
            Set_info['Data']['data'] = Set_info_Dispositon
            Set_info['Parameters']['BufferLength'] = len(Set_info['Data']['data'])
            
        if (fileinfoclass == 20):
            Set_info_EndOfFileInformation = SMBSet_info_EndOfFileInformation()
            Set_info['Data']['data'] = Set_info_EndOfFileInformation
            Set_info['Parameters']['BufferLength'] = len(Set_info['Data']['data'])
      
        return Set_info

def set_info_Response_Structure(set_infoResponse):
        Smb2Constants = constants.smb2Constants()
        #set_infoParameters = SMBSet_infoResponse_Parameters(set_infoResponse['Parameters'])
        #data = set_infoParameters['Buffer']
        return 1

def set_info_Request_Structure(Set_info, fileId, *set_info_params):
        infotypefound = 0
        fileinfoclassfound = 0
        cnt = 0
        while ( cnt < len(set_info_params)):
            tmpstr = set_info_params[cnt]
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
            infotype = 0x01
        if (fileinfoclassfound == 0):
            fileinfoclass = 4

        Set_info1 = set_info_Extend_Request_Structure(Set_info, fileId, infotype, fileinfoclass, *set_info_params)
        return Set_info1