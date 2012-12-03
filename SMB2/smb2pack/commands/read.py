from .. import smb2
from .. import constants
import string

class SMBRead_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x31'),
        ('Padding','<B=0x0'),
        ('Reserved','<B=0x0'),
        ('Length','<I=0x0'),
        ('Offset','<Q=0x0'),
        ('FileId','<16s=""'),
        ('MinimumCount','<I=0x0'),
        ('Channel','<I=0x0'),
        ('RemainingBytes','<I=0x0'),
        ('ReadChannelInfoOffset','<H=0x0'),
        ('ReadChannelInfoLength','<H=0x0'),
    )
class SMBRead_Data(smb2.SMBCommand_Parameters):
    structure = (
#        ('FileName','z'),
#        ('Path','z'),
        ('data','z=""'),
#        ('Next','<I'),
    )
class SMBReadResponse_Parameters(smb2.SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('DataOffset','<B'),
        ('Reserved','<B'),
        ('DataLength','<I'),
        ('DataRemaining','<I'),
        ('Reserved2','<I'),
        ('Buffer',':'),
    )


def read_Extend_Request_Structure(Read, fileId, offset, length):
        Smb2Constants = constants.smb2Constants()
        
        print "offset=",offset, "length=",length
        Read['Parameters'] = SMBRead_Parameters()
        Read['Data'] = SMBRead_Data()

        Read['Parameters']['Length']    = length      
        Read['Parameters']['Offset']      = offset    
        Read['Parameters']['FileId']      = fileId                 
                                                                         
        Read['Data']['data'] = ''
        return Read

def read_Response_Structure(readResponse):
        Smb2Constants = constants.smb2Constants()
        readParameters = SMBReadResponse_Parameters(readResponse['Parameters'])
        data = readParameters['Buffer']
        myfile = file("output.txt", 'a')
        myfile.writelines(data)
        #print len(data)
        myfile.close()
        return 1

def read_Request_Structure(Read, fileId, *read_params):
        offsetfound = 0
        lengthfound =0

#        filename = read_params[0]
        cnt = 0
#        print read_params,len(read_params)
        while ( cnt < len(read_params)):
            tmpstr = read_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'offset') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                offset = eval(tmpstr)
                offsetfound = 1
            elif( string.find(tmpstr, 'length') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                length = eval(tmpstr)
                lengthfound = 1
            cnt += 1

        if (offsetfound == 0):
            offset = 0x0
        if (lengthfound == 0):
            length = 0x0
#        print "test=",offset
        Read1 = read_Extend_Request_Structure(Read, fileId, offset, length)
        return Read1