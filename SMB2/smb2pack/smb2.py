
import os, pdb,sys, socket, string, re, select, errno
import nmb
import types
from random import randint
from struct import *

import ntlmtest
import base64
import ctypes
#from dcerpc import samr
from structure import Structure

unicode_support = 0
unicode_convert = 1

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from binascii import a2b_hex

# Represents a SMB Packet
class NewSMBPacket(Structure):
    structure = (
        ('Component', '"\xfeSMB'),
        ('Hlength','<H=0x40'),
        ('CreditCharge','H=0'),
        ('Status','I=0'),
        ('Command','<H=0x1'),
        ('CreditRe','H=31'),
        ('Flags','<I=0'),
        ('NextCommand','<I=0'),
        ('MessageId','<Q=0'),
        ('Pid','<I=0'),
        ('Tid','<I=0'),
        ('Sid','<Q=0'),
        ('Signature','<16s=""'),
        ('Data','*:'),
    )

    def __init__(self, **kargs):
        Structure.__init__(self, **kargs)

        if not kargs.has_key('data'):
            self['Data'] = []

    def addCommand(self, command):
#        if len(self['Data']) == 0:
        self['Command'] = command.command
#        else:
#            self['Data'][-1]['Parameters']['AndXCommand'] = command.command
#            self['Data'][-1]['Parameters']['AndXOffset'] = len(self)
        self['Data'].append(command)
        

    def isValidAnswer(self, cmd):
        # this was inside a loop reading more from the net (with recv_packet(None))
        if self['Command'] == cmd:
#            if (self['ErrorClass'] == 0x00 and
#                self['ErrorCode']  == 0x00):
#                    return 1
#            elif self.isMoreData():
                return 1
#            raise SessionError, ("SMB Library Error", self['ErrorClass'], self['ErrorCode'])
        else:
            raise UnsupportedFeature, ("Unexpected answer from server: Got %d, Expected %d" % (self['Command'], cmd))

class SMBPacket:
    def __init__(self,data = ''):
        # The uid attribute will be set when the client calls the login() method
        self._hlength = 0x40
        self._padding = 0x0
        self._ntstatus = 0x0
        self._command = 0x0
        self._credits = 0x0
        self._flags = 0x0
        self._chainoffset = 0x0
        self._cmdsqnum = 0x1
        self._pid = 0x0
        self._tid = 0x0
        self._sid = 0x0
        self._signature = '\0' * 16
        self._datasize = 0x0
        self._dialectcount = 0x0
        self._security_mode = 0x0
        self._padding = 0x0
        self._capabilities = 0x0
        self._client_guid = '\0' * 16
        self._clientstarttime = '\0' * 8
        self._dialects = ''
        self._dialectrevision = ''
        self._serverguid = '\0' * 16
        self._MaxTransactSize = 0x0
        self._MaxReadSize = 0x0
        self._MaxWriteSize = 0x0
        self._SystemTime = '\0' * 8
        self._ServerStartTime = '\0' * 8
        self._SecurityBufferOffset = 0x0
        self._SecurityBufferLength = 0x0
        self._buffer = ''
        if data != '':
            self._hlength = unpack('<H',data[4:6])[0]
            self._padding = unpack('<H',data[6:8])[0]
            self._ntstatus = unpack('<I',data[8:12])[0]
            self._command = unpack('<H',data[12:14])[0]
            self._credits = unpack('<H',data[14:16])[0]
            self._flags = unpack('<I',data[16:20])[0]
            self._chainoffset = unpack('<I',data[20:24])[0]
            self._cmdsqnum = unpack('<Q',data[24:32])[0]
            self._pid = unpack('<I',data[32:36])[0]
            self._tid = unpack('<I',data[36:40])[0]
            self._sid = unpack('<Q',data[40:48])[0]
            self._signature = unpack('<16s',data[48:64])[0]
            ############## end of header ###############
            self._datasize = unpack('<H',data[64:66])[0]
            self._security_mode = ord(data[66])
            self._dialectrevision = unpack('<H',data[68:70])[0]
            self._padding = unpack('<H',data[70:72])[0]
            self._serverguid = unpack('<16s',data[72:88])[0]
            self._capabilities = unpack('<I',data[88:92])[0]
            self._MaxTransactSize = unpack('<I',data[92:96])[0]
            self._MaxReadSize = unpack('<I',data[96:100])[0]
            self._MaxWriteSize = unpack('<I',data[100:104])[0]
            self._SystemTime = unpack('<8s',data[104:112])[0]
            self._ServerStartTime = unpack('<8s',data[112:120])[0]
            self._SecurityBufferOffset = unpack('<H',data[120:122])[0]
            self._SecurityBufferLength = unpack('<H',data[122:124])[0]
            self._buffer = data[128:self._SecurityBufferLength]
    def set_command(self,command):
        self._command = command
    def set_flags(self,flags):
        self._flags = flags
    def set_flags2(self, flags2):
        self._flags2 = flags2
    def set_pad(self, pad):
        self._pad = pad
    def set_tid(self,tid):
        self._tid = tid
    def set_pid(self,pid):
        self._pid = os.getpid()
    def set_uid(self,uid):
        self._uid = uid
    def set_buffer(self,buffer):
        if type(buffer) is types.UnicodeType:
            raise Exception('SMBPacket: Invalid buffer. Received unicode')
        self._buffer = buffer
        self._bytecount = len(buffer)
    def set_datasize(self):
        self._datasize = 0x24
    def set_dialects(self,dialects):
        self._dialects = dialects
        self._dialectcount = 0x01
    def setsecurity_mode(self):
        self._security_mode = 0x0
    def capabilities(self,capabilities):
        self._capabilities = 0x0
    def client_guid(self):
        self._client_guid = '\0' * 16     
    def clientstarttime(self):
        self._clientstarttime = '\0' * 8    
    def get_command(self):
        return self._command
    def get_flags(self):
        return self._flags
    def get_flags2(self):
        return self._flags2
    def get_pad(self):
        return self._pad
    def get_tid(self):
        return self._tid
    def get_pid(self):
        return self._pid
    def get_uid(self):
        return self._uid
    def get_buffer(self):
        return self._buffer
    def rawData(self):
        #data = pack('<4sBBHBH12sHHHHB','\xffSMB',self._command,self._error_class,0,\
        #self._error_code,self._flags,self._flags2,self._pad,self._tid, self._pid, \
        #self._uid, self._mid, self._wordcount) + self._parameter_words + pack('<H',self._bytecount) + self._buffer  
        data = pack('<4sHHIHHIIQIIQ16s','\xfeSMB',self._hlength,self._padding,self._ntstatus,\
        self._command,self._credits,self._flags,self._chainoffset,self._cmdsqnum,self._pid, \
        self._tid, self._sid, self._signature) + pack('<HHHHI16s8s',self._datasize,self._dialectcount,\
        self._security_mode,self._padding,\
        self._capabilities,self._client_guid,self._clientstarttime) + self._dialects
        #print calcsize('4sHHIHHIIQIIQ16s')
        return data
    def rawResponseData(self):
        data = pack('<4sHHIHHIIQIIQ16s','\xfeSMB',self._hlength,self._padding,self._ntstatus,\
        self._command,self._credits,self._flags,self._chainoffset,self._cmdsqnum,self._pid, \
        self._tid, self._sid, self._signature) + pack('<HBBHH16sIIII8s8sHH',self._datasize,\
        self._security_mode,self._padding,\
        self._dialectrevision,self._padding,self._serverguid,self._capabilities,\
        self._MaxTransactSize,self._MaxReadSize,self._MaxWriteSize,self._SystemTime,\
        self._ServerStartTime,self._SecurityBufferOffset,self._SecurityBufferLength) + self._buffer
        return data           

   


class SMBCommand(Structure):
    structure = (
#        ('WordCount', 'B=len(Parameters)/2'),
#        ('_ParametersLength','_-Parameters','WordCount*2'),
        ('Parameters',':'),             # default set by constructor
#        ('ByteCount','<H-Data'),
        ('Data',':'),                   # default set by constructor
    )

    def __init__(self, commandOrData = None, data = None, **kargs):
        if type(commandOrData) == type(0):
            self.command = commandOrData
        else:
            data = data or commandOrData

        Structure.__init__(self, data = data, **kargs)

        if data is None:
            self['Parameters'] = ''
            self['Data']       = ''

class AsciiOrUnicodeStructure(Structure):
    def __init__(self, flags = 0, **kargs):
#        if flags & SMB.FLAGS2_UNICODE:
#            self.structure = self.UnicodeStructure
#        else:
        self.structure = self.AsciiStructure
        return Structure.__init__(self, **kargs)

class SMBCommand_Parameters(Structure):
    pass

class SMBAndXCommand_Parameters(Structure):
    commonHdr = (
        #('AndXCommand','B=0xff'),
        #('_reserved','B=0'),
        #('AndXOffset','<H=0'),
        ('StructureSize','<H=0x19'),
    )
    structure = (       # default structure, overriden by subclasses
        ('Data',':=""'),
    )

class SMBSessionSetupAndX_Parameters(SMBAndXCommand_Parameters):

    structure = (
        ('VcNumber','<B'),
        ('SecurityMode','<B'),
        ('Capabilities','<I'),
        ('Channel','<I'),
        ('SecurityBufferOffset','<H'),
        ('SecurityBufferLength','<H'),
#        ('_reserved','<L=0'),
        ('PreviousSessionId','<Q'),
        ('_reservedoid','<Q'),
        ('oid','<H'),
        ('_MechType','<Q'),
        ('_MechType1','<Q'),
        ('_MechType2','<Q'),
#        ('oid1','<H'),
    )

class SMBSessionSetupAndX_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
#        ('oid','_-AnsiPwd'),
#        ('UnicodePwdLength','_-UnicodePwd'),
#        ('AnsiPwd',':=""'),
#        ('UnicodePwd',':=""'),
#        ('Account','z=""'),
#        ('PrimaryDomain','z=""'),
#        ('NativeOS','z=""'),
#        ('NativeLanMan','z=""'),
#        ('MechType','z=""'),
        ('test',':=""'),
    )
    
    UnicodeStructure = (
#        ('AnsiPwdLength','_-AnsiPwd'),
#        ('UnicodePwdLength','_-UnicodePwd'),
#        ('AnsiPwd',':=""'),
#        ('UnicodePwd',':=""'),
#        ('Account','w=""'),
#        ('PrimaryDomain','w=""'),
#        ('NativeOS','w=""'),
#        ('NativeLanMan','w=""'),
#         ('test','z=""'),
    )
class SMBSessionSetup2AndX_Parameters(SMBAndXCommand_Parameters):

    structure = (
        ('VcNumber','<B'),
        ('SecurityMode','<B'),
        ('Capabilities','<I'),
        ('Channel','<I'),
        ('SecurityBufferOffset','<H'),
        ('SecurityBufferLength','<H'),
        ('PreviousSessionId','<Q'),
        ('_reserved','<Q=0'),
#        ('_reserved1','<I=0'),
        ('negresult','<B=0'),
        ('_reserved2','<Q=0'),
    )

class SMBSessionSetup2AndX_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('test',':=""'),
        ('Tag3','<H=0'),
        ('OctetStringHeader','<H=0'),
        ('MechListMicVersion','<I=0'),
        ('Checksum1','<B=0'),
        ('Checksum2','<B=0'),
        ('Checksum3','<B=0'),
        ('Checksum4','<B=0'),
        ('Checksum5','<B=0'),
        ('Checksum6','<B=0'),
        ('Checksum7','<B=0'),
        ('Checksum8','<B=0'),
        ('SeqNum','<I=0'),
    )

#class SMBSessionSetupAndXResponse_Parameters(SMBAndXCommand_Parameters):
#    structure = (
##        ('StructureSize','<H'),
#        ('SessionFlags','<H'),
#        ('SecurityBufferOffset','<H'),
#        ('SecurityBufferLength','<H'),
#        ('ignore1','<Q'),
#        ('ignore2','<Q'),
#        ('ignore3','<B'),
#        ('_MechType','<Q'),
#        ('_MechType1','<Q'),
#        ('ntlm_ssp',':'),
#    )

class SMBSessionSetupAndXResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H'),
        ('SessionFlags','<H'),
        ('SecurityBufferOffset','<H'),
        ('SecurityBufferLength','<H'),
        ('Asnid','<B'),
        ('LengthOfLength','<B'),
        ('Length',':'),
    )
class SMBSessionSetupNegtokenResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('Asnid','<B'),
        ('LengthOfLength','<B'),
        ('Length',':'),
    )
class SMBSessionSetupNegtokenResponse_Parameters1(SMBCommand_Parameters):
    structure = (
        ('Tag0','<H'),
        ('Negstate','<3s'),
        ('Tag1','<H'),
        ('SupportedMech','<12s'),
        ('Tag2','<3s'),
        ('ostringheader','<3s'),
        ('ntlmsspResponseToken',':'),
    )

class SMBSessionSetupAndXResponse_Data(SMBCommand_Parameters):
    AsciiStructure = (
    )

#    UnicodeStructure = (
#        ('NativeOS','w=""'),
#        ('NativeLanMan','w=""'),
#        ('PrimaryDomain','w=""'),
#    )
################################################################################################
class SMBLogOff_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x4'),
        ('Reserved','<H=0x0'),
    )

class SMBTreeDisconnect_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x4'),
        ('Reserved','<H=0x0'),
    )

class SMBClose_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x18'),
        ('Flags','<H=0x0'),
        ('Reserved','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBFlush_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x18'),
        ('Reserved','<H=0x0'),
        ('Reserved1','<I=0x0'),
        ('FileId','<16s=""'),
    )
class SMBWrite_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x31'),
        ('DataOffset','<H=0x0'),
        ('Length','<I=0x0'),
        ('Offset','<Q=0x0'),
        ('FileId','<16s=""'),
        ('MinimumCount','<I=0x0'),
        ('Channel','<I=0x0'),
        ('RemainingBytes','<I=0x0'),
        ('WriteChannelInfoOffset','<H=0x0'),
        ('WriteChannelInfoLength','<H=0x0'),
        ('Flags','<I=0x0'),
    )
class SMBWrite_Data(SMBCommand_Parameters):
    structure = (
        ('data','z=""'),
    )
class SMBCancel_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x4'),
        ('Reserved','<H=0x0'),
    )
class SMBEcho_Parameters(SMBCommand_Parameters):
    structure = (
        ('StructureSize','<H=0x4'),
        ('Reserved','<H=0x0'),
    )
    

################################################################################################

class NTLMDialect(SMBPacket):
    def __init__(self,data=''):
        SMBPacket.__init__(self,data)
        self._selected_dialect = 0
        self._security_mode = 0
        self._max_mpx = 0
        self._max_vc = 0
        self._max_buffer = 0
        self._max_raw = 0
        self._session_key = 0
        self._lsw_capabilities = 0
        self._msw_capabilities = 0
        self._utc_high = 0
        self._utc_low = 0
        self._minutes_utc = 0
        self._encryption_key_len = 0
        self._encryption_key = ''
        self._server_domain = ''
        self._server_name = ''
        if data:
#            self._selected_dialect, self._security_mode, self._max_mpx, self._max_vc = unpack('<HBHH',self.get_parameter_words()[:7])
#            self._max_buffer,self._max_raw, self._session_key, self._lsw_capabilities, self._msw_capabilities = unpack('<lllHH', self.get_parameter_words()[7:16+7])
#            self._utc_low, self._utc_high,self._minutes_utc, self._encryption_key_len = unpack('<LLhB',self.get_parameter_words()[23:34])
            self._selected_dialect, self._security_mode = unpack('<H',data[68:70])[0], ord(data[66])
            self._utc_low, self._utc_high = unpack('<L',data[104:108])[0], unpack('<L',data[108:112])[0]
            if self._encryption_key_len > 0 and len(self.get_buffer()) >= self._encryption_key_len:
                self._encryption_key = self.get_buffer()[:self._encryption_key_len]
                buf = self.get_buffer() 
                # Look for the server domain offset
                self._server_name = '<Unknown>'
                self._server_domain = '<Unknown>'
                try:
                    if self._lsw_capabilities & 0x3: # is this unicode?
                         offset = self._encryption_key_len
                         if offset & 0x01:
                            offset += 1
                         end = offset
                         while ord(buf[end]) or ord(buf[end+1]):
                             end += 2
                         self._server_domain = unicode(buf[offset:end],'utf_16_le')
                         end += 2
                         offset = end
                         while ord(buf[end]) or ord(buf[end+1]):
                             end += 2
                         self._server_name = unicode(buf[offset:end],'utf_16_le')
                    else:
                         offset = self._encryption_key_len
                         idx1 = string.find(buf,'\0',offset)
                         if idx1 != -1:
                            self._server_domain = buf[offset:idx1]
                            idx2 = string.find(buf, '\0', idx1 + 1)
                            if idx2 != -1:
                               self._server_name = buf[idx1+1:idx2]
                except:
                    pass
            else:
                self._encryption_key = ''
 
    def get_selected_dialect(self):
        return self._selected_dialect
    def get_security_mode(self):
        return self._security_mode
    def get_max_mpx(self):
        return self._max_mpx
    def get_max_vc(self):
        return self._max_vc
    def get_max_buffer(self):
        return self._max_buffer
    def get_max_raw(self):
        return self._max_raw
    def get_lsw_capabilities(self):
        return self._lsw_capabilities
    def get_msw_capabilities(self):
        return self._msw_capabilities
    def get_utc(self):
        return self._utc_high, self._utc_low
    def get_minutes_utc(self):
        return self._minutes_utc
    def get_encryption_key_len(self):
        return self._encryption_key_len
    def get_encryption_key(self):
        return self._encryption_key
    def is_auth_mode(self):
        return self._security_mode & SMB.SECURITY_AUTH_MASK
    def is_share_mode(self):
        return self._security_mode & SMB.SECURITY_SHARE_MASK
    def is_rawmode(self):
        return self._lsw_capabilities & SMB.CAP_RAW_MODE
                
                
class SMB:

    # SMB2 Command Codes
    SMB2_COM_NEGOTIATE = 0x0
    SMB2_COM_SESSION_SETUP_ANDX = 0x0001
    SMB2_COM_LOGOFF = 0x0002
    SMB2_COM_TREE_CONNECT = 0x0003
    SMB2_COM_TREE_DISCONNECT = 0x0004
    SMB2_COM_CREATE = 0x0005
    SMB2_COM_CLOSE = 0x0006
    SMB2_COM_FLUSH = 0x0007
    SMB2_COM_READ = 0x0008
    SMB2_COM_WRITE = 0x0009
    SMB2_COM_LOCK = 0x000A
    SMB2_COM_IOCTL = 0x000B
    SMB2_COM_CANCEL = 0x000C
    SMB2_COM_ECHO = 0x000D
    SMB2_COM_QUERY_DIRECTORY = 0x000E
    SMB2_COM_CHANGE_NOTIFY = 0x000F
    SMB2_COM_QUERY_INFO = 0x0010
    SMB2_COM_SET_INFO = 0x0011
    SMB2_COM_OPLOCK_BREAK = 0x0012
   
    # SMB2 ImpersonationLevel
    SMB2_Anonymous = 0x00000000
    SMB2_Identification = 0x00000001
    SMB2_Impersonation = 0x00000002
    SMB2_Delegate = 0x00000003
    
    # Security Share Mode (Used internally by SMB class)
    SECURITY_SHARE_MASK = 0x01
    SECURITY_SHARE_SHARE = 0x00
    SECURITY_SHARE_USER = 0x01
    
    # Security Auth Mode (Used internally by SMB class)
    SECURITY_AUTH_MASK = 0x02
    SECURITY_AUTH_ENCRYPTED = 0x02
    SECURITY_AUTH_PLAINTEXT = 0x00

    # Raw Mode Mask (Used internally by SMB class. Good for dialect up to and including LANMAN2.1)
    RAW_READ_MASK = 0x01
    RAW_WRITE_MASK = 0x02

    # Capabilities Mask (Used internally by SMB class. Good for dialect NT LM 0.12)
    CAP_RAW_MODE = 0x0001
    CAP_MPX_MODE = 0x0002
    CAP_UNICODE = 0x0004
    CAP_LARGE_FILES = 0x0008
    CAP_EXTENDED_SECURITY = 0x80000000

    def __init__(self, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = nmb.NETBIOS_SESSION_PORT, timeout=None):
        # The uid attribute will be set when the client calls the login() method
        self.__uid = 0
        self.__server_os = ''
        self.__server_lanman = ''
        self.__server_domain = ''
        remote_name = "*SMBSERVER"
        self.__remote_name = string.upper(remote_name)
        self.__is_pathcaseless = 0
        self.__ntlm_dialect = 0
        self.__sess = None
        self.__sid = 0
        self.__msgid = 1
        self.__tid = 1
        
			
        if timeout==None:
            self.__timeout = 30
        else:
            self.__timeout = timeout
        
        if not my_name:
            my_name = socket.gethostname()
            i = string.find(my_name, '.')
            if i > -1:
                my_name = my_name[:i]

        try:
            self.__sess = nmb.NetBIOSSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)
        except socket.error, ex:
            raise ex

        # Initialize values __ntlm_dialect, __is_pathcaseless
        self.__neg_session()
        
        # If the following assertion fails, then mean that the encryption key is not sent when
        # encrypted authentication is required by the server.
        assert (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_PLAINTEXT) or \
        (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_ENCRYPTED and \
        self.__ntlm_dialect.get_encryption_key() and self.__ntlm_dialect.get_encryption_key_len() >= 8)

        # Call login() without any authentication information to setup a session if the remote server
        # is in share mode.
        if self.__ntlm_dialect.is_share_mode() == SMB.SECURITY_SHARE_SHARE:
           self.login('', '')
            
    def set_timeout(self, timeout):
        self.__timeout = timeout
        
    def __del__(self):
        if self.__sess:
            self.__sess.close()

    def recvSMB(self):
        r = self.__sess.recv_packet(self.__timeout)
        return NewSMBPacket(data = r.get_trailer())
    
    def recv_packet(self):
        r = self.__sess.recv_packet(self.__timeout)
        return SMBPacket(r.get_trailer())
    
    def sendSMB(self,smb):
#        smb['Uid'] = self.__uid
        smb['Pid'] = os.getpid()
        self.__sess.send_packet(str(smb))

        
    def send_smb(self,s):
        s.set_uid(self.__uid)
        s.set_pid(os.getpid())
        self.__sess.send_packet(s.rawData())

    def __send_smb_packet(self, cmd, flags, flags2, tid, mid, params = '', data = ''):
        smb = NewSMBPacket()
        smb['Flags'] = flags
        smb['Flags2'] = flags2
        smb['Tid'] = tid
        smb['Mid'] = mid
        cmd = SMBCommand(cmd)
        smb.addCommand(cmd)

        cmd['Parameters'] = params
        cmd['Data'] = data
        self.sendSMB(smb)

    def isValidAnswer(self, s, cmd):
        while 1:
#            if s.rawData():
                if s.get_command() == cmd:
#                    if s.get_error_class() == 0x00 and s.get_error_code() == 0x00:
                     return 1
#                    else:
#                        raise SessionError, ( "SMB Library Error", s.get_error_class(), s.get_error_code())
                else:
                    raise SessionError("Invalid command received. %x" % cmd)
                    break
#            s=self.recv_packet(None)   
        return 0
    
    def __neg_session(self):
        self.__sess.send_packet("\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00\x78\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00")
        self.__sess.recv_packet() #skiping smb2 negotiate response for smb negotiate request
        s = SMBPacket()
        s.set_command(SMB.SMB2_COM_NEGOTIATE)
        s.set_datasize()
#        s.set_dialects('\x02\x02\x10\x02\x02NT LM 0.12\x00')
        s.set_dialects('\x02\x02')
        s.setsecurity_mode()
        s.capabilities('\x00')
        s.client_guid()
        s.clientstarttime()
        #s.set_buffer('\x02PC NETWORK PROGRAM 1.0\x00'+'\x02LANMAN1.0\x00'+'\x02Windows for Workgroups 3.1a\x00'+'\x02LM1.2X002\x00'+'\x02LANMAN2.1\x00'+'\x02NT LM 0.12\x00'+'\x02SMB 2.002\x00'+'\x02SMB 2.???\x00')
#        s.set_buffer('\x02NT LM 0.12\x00')
        self.send_smb(s)

        while 1:
            s = self.recv_packet()
#            pdb.set_trace()
#            print s._hlength,s._datasize,s._MaxTransactSize,s._SystemTime,s._SecurityBufferLength,s._buffer
            if self.isValidAnswer(s,SMB.SMB2_COM_NEGOTIATE):
                self.__ntlm_dialect = NTLMDialect(s.rawResponseData())
#                if self.__ntlm_dialect.get_selected_dialect() == 0xffff:
#                    raise UnsupportedFeature,"Remote server does not know NT LM 0.12"
#
#                #NL LM 0.12 dialect selected
#                if self.__ntlm_dialect.get_lsw_capabilities() & SMB.CAP_EXTENDED_SECURITY:
#                    raise UnsupportedFeature, "This version of pysmb does not support extended security validation. Please file a request for it."
#
#                self.__is_pathcaseless = s.get_flags() & SMB.FLAGS1_PATHCASELESS
                print "negotiate"
                return 1
            else:
                return 0


    def tree_connect(self,*tree_connect_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        
        Tree_connect = SMBCommand(SMB.SMB2_COM_TREE_CONNECT)
        from commands import tree_connect
        Tree_connect1 = tree_connect.tree_connect_Request_Structure(Tree_connect, *tree_connect_params)
        smb.addCommand(Tree_connect1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_TREE_CONNECT):
                print "Tree_connect"
            if smb['Status'] != 0x0:
                print "Tree_connect Error status=",hex(smb['Status'])
                status,sid,tid =0,0,0
            else:    
                tree_connectResponse   = SMBCommand(smb['Data'][0])
                Capabilities = tree_connect.tree_connect_Response_Structure(tree_connectResponse)
            return smb['Status'],smb['Sid'],smb['Tid']
    
            
    def get_ntlmv1_response(self, key):
        challenge = self.__ntlm_dialect.get_encryption_key()
        return ntlmtest.get_ntlmv1_response(key, challenge)

    def hmac_md5(self, key, data):
        import POW
        h = POW.Hmac(POW.MD5_DIGEST, key)
        h.update(data)
        result = h.mac()
        return result

    def get_ntlmv2_response(self, hash):
        """
        blob = RandomBytes( blobsize );
        data = concat( ServerChallenge, 8, blob, blobsize );
        hmac = hmac_md5( v2hash, 16, data, (8 + blobsize) );
        v2resp = concat( hmac, 16, blob, blobsize );
        """
        return ''

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
        if password != '' or (password == '' and lmhash == '' and nthash == ''):
            self.login_plaintext_password(user, password)
        elif lmhash != '' or nthash != '':
            self.login_pass_the_hash(user, lmhash, nthash, domain)

    def _login(self, user, pwd_ansi, pwd_unicode, domain = ''):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        
    
        sessionSetup = SMBCommand(SMB.SMB2_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['VcNumber']        = 0
        sessionSetup['Parameters']['SecurityMode']      = 0x01
        sessionSetup['Parameters']['Capabilities']         = 0x00000001
        sessionSetup['Parameters']['Channel']       = 0
        sessionSetup['Parameters']['SecurityBufferOffset']    = 0x58
        sessionSetup['Parameters']['SecurityBufferLength'] = 34
        sessionSetup['Parameters']['PreviousSessionId']     = 0x0
#        print hex(len(smb)+len(sessionSetup['Parameters']))
        sessionSetup['Parameters']['_reservedoid']     = 0x0501062b06064860
        sessionSetup['Parameters']['oid']  = 0x0205
        sessionSetup['Parameters']['_MechType']     = 0x0c300ea03c303ea0
        sessionSetup['Parameters']['_MechType1']    = 0x82010401062b0a06
        sessionSetup['Parameters']['_MechType2']    = 0x28042aa20a020237
        

#        sessionSetup['Data']['AnsiPwd']       = pwd_ansi
#        sessionSetup['Data']['UnicodePwd']    = pwd_unicode
#        sessionSetup['Data']['Account']       = str(user)
#        sessionSetup['Data']['PrimaryDomain'] = str(domain)
#        sessionSetup['Data']['NativeOS']      = str(os.name)
#        sessionSetup['Data']['NativeLanMan']  = 0x00000058
#        sessionSetup['Data']['oid']  = 0x2b0601050502
#        test11= ntlm.NTLMAuthNegotiate()
#        test11= ntlm4.create_NTLM_NEGOTIATE_MESSAGE
        test11 = ntlmtest.create_NTLM_NEGOTIATE_MESSAGE("corp\\aryaka")
#        test11 = StringIO(base64.b64decode(created_negotiate_b64))
        #negotiate_message = ntlm2.NTLMMessage.read(f)
        #negotiate_message.verify()

#        test11= ntlm4.create_NTLM_NEGOTIATE_MESSAGE('aryaka')
#        test11 = ntlm5.create_message1()
#        print unpack(test11)
        #test11 = test11[8:]
        sessionSetup['Data']['test']  = test11
#        print len(sessionSetup['Data'])
        sessionSetup['Parameters']['SecurityBufferLength'] =len(sessionSetup['Data']) + 34


        smb.addCommand(sessionSetup)
#        smb['Pid'] = os.getpid()
#        print str(smb),test11
        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB2_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self.__sid = smb['Sid']
            print "sessionSetup1"
#            print hex(smb['Sid'])
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
            LengthOfLength = sessionParameters['LengthOfLength'] - 0x80
            BufferData = sessionParameters['Length']
            BufferData = BufferData[LengthOfLength:]
            
            sessionParameters = SMBSessionSetupNegtokenResponse_Parameters(BufferData)
            LengthOfLength = sessionParameters['LengthOfLength'] - 0x80
            BufferData = sessionParameters['Length']
            BufferData = BufferData[LengthOfLength:]
            
            sessionParameters = SMBSessionSetupNegtokenResponse_Parameters1(BufferData)
            BufferData = sessionParameters['ntlmsspResponseToken']
            
            
            ntlmauthchallenge = ntlmtest.NTLMAuthChallenge(BufferData)
#            ServerChallenge, NegotiateFlags = ntlm4.parse_NTLM_CHALLENGE_MESSAGE()
            challenge = ntlmauthchallenge['challenge']
            domainname = ntlmauthchallenge['domain_name']
#            print domainname,len(domainname)
            self._login1(user, pwd_ansi, pwd_unicode, challenge ,domain)
#            self._login1(user, pwd_ansi, pwd_unicode, challenge ,domain)

#            print len(sessionParameters['ntlm_ssp']),len(sessionParameters),len(sessionResponse['Parameters']),len(sessionResponse['Data'])
#            sessionData = SMBSessionSetupAndXResponse_Data(sessionResponse['Data'])
#            print len(sessionData)
#            sessionData       = SMBSessionSetupAndXResponse_Data(data = sessionResponse['Data'])
            

#            self.__server_os     = sessionData['NativeOS']
#            self.__server_lanman = sessionData['NativeLanMan']
#            self.__server_domain = sessionData['PrimaryDomain']
#
            return 1
#        else: raise Exception('Error: Could not login successfully')

    def _login1(self, user, pwd_ansi, pwd_unicode, challenge, domain = ''):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
    
        sessionSetup = SMBCommand(SMB.SMB2_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetup2AndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetup2AndX_Data()

        sessionSetup['Parameters']['VcNumber']        = 0
        sessionSetup['Parameters']['SecurityMode']      = 0x01
        sessionSetup['Parameters']['Capabilities']         = 0x00000001
        sessionSetup['Parameters']['Channel']       = 0
        sessionSetup['Parameters']['SecurityBufferOffset']    = 0x58
        sessionSetup['Parameters']['PreviousSessionId']     = 0x0
        sessionSetup['Parameters']['_reserved']     = 0x03a0e98130ec81a1
#        sessionSetup['Parameters']['_reserved1']    = 0x010a03a0
        sessionSetup['Parameters']['negresult']     = 0x0a
        sessionSetup['Parameters']['_reserved2']    = 0xca8104cd81a20101

#        test11= ntlm.NTLMAuthChallengeResponse(user, pwd_ansi ,challenge)
        NegotiateFlags = 0x8201
#        ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
        test11 = ntlmtest.create_NTLM_AUTHENTICATE_MESSAGE(challenge, "aryaka", "CORP", "Aryak@123", NegotiateFlags)
#        ServerChallenge = ntlm4.HexToByte("01 23 45 67 89 ab cd ef")
#        print ServerChallenge,challenge,ntlm4.ByteToHex(challenge)
#        print user, pwd_ansi ,challenge,len(challenge)
        #test11 = test11[8:]
#        test11 = test11#[:len(test11)-1]
#        sessionSetup['Data']['test'] = sessionSetup['Data']['test'][:145]
 
        sessionSetup['Data']['test']  = test11
        sessionSetup['Data']['Tag3']  = 0x12a3
        sessionSetup['Data']['OctetStringHeader']  = 0x1004
        sessionSetup['Data']['MechListMicVersion']  = 0x1
        sessionSetup['Data']['Checksum1']  = 0x6D
        sessionSetup['Data']['Checksum2']  = 0xAB
        sessionSetup['Data']['Checksum3']  = 0xF2
        sessionSetup['Data']['Checksum4']  = 0x5B
        sessionSetup['Data']['Checksum5']  = 0x21
        sessionSetup['Data']['Checksum6']  = 0x59
        sessionSetup['Data']['Checksum7']  = 0x1C
        sessionSetup['Data']['Checksum8']  = 0x73
        sessionSetup['Data']['SeqNum']     = 0x0
        sessionSetup['Parameters']['SecurityBufferLength'] =len(sessionSetup['Data'] ) + 17


        smb.addCommand(sessionSetup)

        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB2_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self.__sid = smb['Sid']
            sessionResponse   = SMBCommand(smb['Data'][0])
            print "sessionSetup2"
##            sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
##            ntlmauthchallenge = ntlm.NTLMAuthChallenge(sessionParameters['ntlm_ssp'])
##            challenge = ntlmauthchallenge['challenge']
#            print len(sessionParameters['ntlm_ssp']),len(sessionParameters),len(sessionResponse['Parameters']),len(sessionResponse['Data'])
#            sessionData = SMBSessionSetupAndXResponse_Data(sessionResponse['Data'])
#            print len(sessionData)
#            sessionData       = SMBSessionSetupAndXResponse_Data(data = sessionResponse['Data'])

#            self.__server_os     = sessionData['NativeOS']
#            self.__server_lanman = sessionData['NativeLanMan']
#            self.__server_domain = sessionData['PrimaryDomain']
#
            return 1
#        else: raise Exception('Error: Could not login successfully')


    def login_pass_the_hash(self, user, lmhash, nthash, domain = ''):
        if len(lmhash) % 2:     lmhash = '0%s' % lmhash
        if len(nthash) % 2:     nthash = '0%s' % nthash

        if lmhash: lmhash = self.get_ntlmv1_response(a2b_hex(lmhash))
        if nthash: nthash = self.get_ntlmv1_response(a2b_hex(nthash))

        self._login(user, lmhash, nthash, domain)

    def login_plaintext_password(self, name, password, domain = ''):
        # Password is only encrypted if the server passed us an "encryption key" during protocol dialect negotiation
        if password and self.__ntlm_dialect.get_encryption_key():
            lmhash = ntlmtest.compute_lmhash(password)
            nthash = ntlmtest.compute_nthash(password)
            lmhash = self.get_ntlmv1_response(lmhash)
            nthash = self.get_ntlmv1_response(nthash)
        else:
            lmhash = password
            nthash = ''
        self._login(name, lmhash, nthash, domain)

    def logoff(self):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        logOff = SMBCommand(SMB.SMB2_COM_LOGOFF)
        logOff['Parameters'] = SMBLogOff_Parameters()
        smb.addCommand(logOff)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_LOGOFF):
                print "logoff"
            if smb['Status'] != 0x0:
                print "logoff Error status=",hex(smb['Status'])
            return smb['Status']
            
    def tree_disconnect(self, tid):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid']  = tid
        TreeDisconnect = SMBCommand(SMB.SMB2_COM_TREE_DISCONNECT)
        TreeDisconnect['Parameters'] = SMBTreeDisconnect_Parameters()
        smb.addCommand(TreeDisconnect)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_TREE_DISCONNECT):
                print "tree_disconnect"
            if smb['Status'] != 0x0:
                print "tree_disconnect Error status=",hex(smb['Status'])
            return smb['Status']
            

    def create(self, tid, *create_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Create = SMBCommand(SMB.SMB2_COM_CREATE)
        from commands import create
        Create1 = create.create_Request_Structure(Create, *create_params)
        smb.addCommand(Create1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_CREATE):
                print "Create"
            if smb['Status'] != 0x0:
                print "Create Error status=",hex(smb['Status'])
                FileId,filesize=0,0
            else:    
                createResponse   = SMBCommand(smb['Data'][0])
                FileId,filesize= create.create_Response_Structure(createResponse)
            return smb['Status'],FileId,filesize

            
    def close(self, tid, fileId):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Close = SMBCommand(SMB.SMB2_COM_CLOSE)
        Close['Parameters'] = SMBClose_Parameters()
        Close['Parameters']['FileId']  = fileId
        smb.addCommand(Close)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_CLOSE):
                print "close"
            if smb['Status'] != 0x0:
                print "close Error status=",hex(smb['Status'])
            return smb['Status']

            
    def flush(self,fileId):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        Flush = SMBCommand(SMB.SMB2_COM_FLUSH)
        Flush['Parameters'] = SMBFlush_Parameters()
        Flush['Parameters']['FileId']  = fileId
        smb.addCommand(Flush)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_FLUSH):
            	 print "flush"
            if smb['Status'] != 0x0:
                print "flush Error status=",hex(smb['Status'])
            return 1
                
    def read(self, tid, fileId, filesize, *read_params):
        cnt,length,offset = 0,-1,-1
#        print len(read_params)
        while ( cnt < len(read_params)):
            tmpstr = read_params[cnt]
            tmpstr = tmpstr.strip()
            tmpstr = tmpstr.lower()
            if( string.find(tmpstr, 'length') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                length = eval(tmpstr)
                lengthfound = 1
            elif( string.find(tmpstr, 'offset') != -1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                offset = eval(tmpstr)
                offsetfound = 1
            cnt += 1
        eof = length
        os.remove("output.txt")#####remove existing output.txt file at client side
        if length == -1:
        	  print 'Read entire file' 
        	  eof = filesize
        if offset == -1:
           start_offset = 0
        else:
        	  start_offset = offset 
        end_offset = eof
        tempeof = eof
        if (eof > 32768):
             while ( tempeof > 32768 ):
                 read_bytes = 32768
                 ntstatus = self.read_andx_request(tid, fileId, "offset="+str(start_offset), "length=32768")
                 #time.sleep(1)
                 start_offset += read_bytes
                 tempeof -= read_bytes
             ntstatus = self.read_andx_request(tid, fileId, "offset="+str(start_offset), "length="+str(tempeof))
        else:
             ntstatus = self.read_andx_request(tid, fileId, "offset="+str(start_offset), "length="+str(tempeof))
        return ntstatus
            
                                        
                               
    def read_andx_request(self, tid, fileId, *read_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Read = SMBCommand(SMB.SMB2_COM_READ)
        from commands import read
        Read1 = read.read_Request_Structure(Read, fileId, *read_params)
        smb.addCommand(Read1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_READ):
                print "Read"
            if smb['Status'] != 0x0:
                print "Read Error status=",hex(smb['Status'])
            else:
                readResponse   = SMBCommand(smb['Data'][0])
                data = read.read_Response_Structure(readResponse)
            #print data
            return smb['Status']

    def write(self, tid, fileId, *write_params):
        offsetfound = 0
        datafound = 0
        filenamefound = 0
        cnt = 0
        while ( cnt < len(write_params)):
            tmpstr = write_params[cnt]
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
            elif( string.find(tmpstr, 'filename') !=-1):
                tmpstr = (tmpstr[(string.find(tmpstr,'=')+1):]).strip()
                filename = tmpstr
                filenamefound = 1
            cnt += 1

        if (offsetfound == 0):
            offset = 0x0
        if (datafound == 0):
            data = ''
        if (filenamefound == 0):
            filename = 'output.txt'
        else:
           try:
               myfile = open(filename, 'r')
               entirefile = myfile.read()
               eof = len(entirefile)
               start_offset = offset
               tempeof = eof
               if (eof > 32768):
                    while ( tempeof > 32768 ):
                        read_bytes = 32768
                        end_offset = start_offset+32768
                        line = entirefile[start_offset:end_offset]
                        ntstatus = self.write_andx_request(tid, fileId, "offset="+str(start_offset), "data="+str(line))
                        start_offset += read_bytes
                        tempeof -= read_bytes
                    end_offset = start_offset+tempeof
                    line = entirefile[start_offset:start_offset+tempeof]
                    ntstatus = self.write_andx_request(tid, fileId, "offset="+str(start_offset), "data="+str(line))
               else:
                    ntstatus = self.write_andx_request(tid, fileId, "offset="+str(offset), "data="+str(entirefile))
#               ######333
#               for line in myfile:
#                  print line
#                  line = line + '\n'
#                  #print len(line)
#                  ntstatus = self.write_andx_request(tid, fileId, "offset="+str(offset), "data="+str(line))
#                  offset = len(line) + offset
               myfile.close()
               return ntstatus
           except IOError:
               print "The file does not exist, exit"
        ntstatus = self.write_andx_request(tid, fileId, "offset="+str(offset), "data="+str(data))
        return ntstatus
             
              
    def write_andx_request(self, tid, fileId, *write_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Write = SMBCommand(SMB.SMB2_COM_WRITE)
        from commands import write
        Write1 = write.write_Request_Structure(Write, fileId, *write_params)
        smb.addCommand(Write1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_WRITE):
                print "Write"
            if smb['Status'] != 0x0:
                print "Write Error status=",hex(smb['Status'])
            else:
                writeResponse   = SMBCommand(smb['Data'][0])
                data = write.write_Response_Structure(writeResponse)
            return smb['Status']
                       
#    def write(self):
#        smb = NewSMBPacket()
#        self.__msgid = self.__msgid + 1
#        smb['MessageId']  = self.__msgid
#        smb['Sid']  = self.__sid
#        Write = SMBCommand(SMB.SMB2_COM_WRITE)
#        Write['Parameters'] = SMBWrite_Parameters()
#        Write['Data'] = SMBWrite_Data()
#        smb.addCommand(Write)
#        self.sendSMB(smb)
#        while 1:
#            smb = self.recvSMB()
#            if smb.isValidAnswer(SMB.SMB2_COM_WRITE):
#                return 1
#

    def lock(self, tid, fileId, *lock_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Lock = SMBCommand(SMB.SMB2_COM_LOCK)
        from commands import lock
        Lock1 = lock.lock_Request_Structure\
                            (Lock, fileId, *lock_params)
        smb.addCommand(Lock1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_LOCK):
                print "Lock"
            if smb['Status'] != 0x0:
                print "Lock Error status=",hex(smb['Status'])
            else:
                lockResponse   = SMBCommand(smb['Data'][0])
                data = lock.lock_Response_Structure(lockResponse,fileInfo)
            return smb['Status']
            

    def ioctl(self, tid, fileId, *ioctl_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Ioctl = SMBCommand(SMB.SMB2_COM_IOCTL)
        from commands import ioctl
        Ioctl1 = ioctl.ioctl_Request_Structure\
                            (Ioctl, fileId, *ioctl_params)
        smb.addCommand(Ioctl1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_IOCTL):
                print "Ioctl"
            if smb['Status'] != 0x0:
                print "Ioctl Error status=",hex(smb['Status'])
            else:
                ioctlResponse   = SMBCommand(smb['Data'][0])
                data = ioctl.ioctl_Response_Structure(ioctlResponse,fileInfo)
            return smb['Status']
            
    def cancel(self,msgId):
        smb = NewSMBPacket()
#        self.__msgid = self.__msgid + 1
        smb['MessageId']  = msgId#self.__msgid
        smb['Sid']  = self.__sid
        Cancel = SMBCommand(SMB.SMB2_COM_CANCEL)
        Cancel['Parameters'] = SMBCancel_Parameters()
        smb.addCommand(Cancel)
        self.sendSMB(smb)
        return 1


            
    def echo(self):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        Echo = SMBCommand(SMB.SMB2_COM_ECHO)
        Echo['Parameters'] = SMBEcho_Parameters()
        smb.addCommand(Echo)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_ECHO):
                return 1

                
    def query_directory(self, tid, fileId, *query_directory_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Query_directory = SMBCommand(SMB.SMB2_COM_QUERY_DIRECTORY)
        from commands import query_directory
        Query_directory1,fileInfo = query_directory.query_directory_Request_Structure\
                            (Query_directory, fileId, *query_directory_params)
        smb.addCommand(Query_directory1)
        self.sendSMB(smb)
        data,cnt = 0,0
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_QUERY_DIRECTORY):
                print "Query_directory"
            if smb['Status'] != 0x0:
                print "Query_directory Error status=",hex(smb['Status'])
            else:
                query_directoryResponse   = SMBCommand(smb['Data'][0])
                data,cnt = query_directory.query_directory_Response_Structure(query_directoryResponse,fileInfo)
            return smb['Status'],data,cnt
            

    def change_notify(self, tid, fileId, *change_notify_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Change_notify = SMBCommand(SMB.SMB2_COM_CHANGE_NOTIFY)
        from commands import change_notify
        Change_notify1 = change_notify.change_notify_Request_Structure(Change_notify, fileId, *change_notify_params)
        smb.addCommand(Change_notify1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_CHANGE_NOTIFY):
                print "Change_notify"
            if smb['Status'] != 0x0:
                print "Change_notify Error status=",hex(smb['Status'])
            else:
                change_notifyResponse   = SMBCommand(smb['Data'][0])
                data = change_notify.change_notify_Response_Structure(change_notifyResponse)
            return smb['Status']


    def query_info(self, tid, fileId, *query_info_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Query_info = SMBCommand(SMB.SMB2_COM_QUERY_INFO)
        from commands import query_info
        Query_info1 = query_info.query_info_Request_Structure(Query_info, fileId, *query_info_params)
        smb.addCommand(Query_info1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_QUERY_INFO):
                print "Query_info"
            if smb['Status'] != 0x0:
                print "Query_info Error status=",hex(smb['Status'])
            else:
                query_infoResponse   = SMBCommand(smb['Data'][0])
                data = query_info.query_info_Response_Structure(query_infoResponse)
            return smb['Status']

           
    def set_info(self, tid, fileId, *set_info_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Set_info = SMBCommand(SMB.SMB2_COM_SET_INFO)
        from commands import set_info
        Set_info1 = set_info.set_info_Request_Structure(Set_info, fileId, *set_info_params)
        smb.addCommand(Set_info1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_SET_INFO):
                print "Set_info"
            if smb['Status'] != 0x0:
                print "Set_info Error status=",hex(smb['Status'])
            else:
                set_infoResponse   = SMBCommand(smb['Data'][0])
                data = set_info.set_info_Response_Structure(set_infoResponse)
            return smb['Status']
            

    def oplock_break(self, tid, fileId, *oplock_break_params):
        smb = NewSMBPacket()
        self.__msgid = self.__msgid + 1
        smb['MessageId']  = self.__msgid
        smb['Sid']  = self.__sid
        smb['Tid'] = tid
        Oplock_break = SMBCommand(SMB.SMB2_COM_OPLOCK_BREAK)
        from commands import oplock_break
        Oplock_break1 = oplock_break.oplock_break_Request_Structure\
                            (Oplock_break, fileId, *oplock_break_params)
        smb.addCommand(Oplock_break1)
        self.sendSMB(smb)
        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB2_COM_OPLOCK_BREAK):
                print "Oplock_break"
            if smb['Status'] != 0x0:
                print "Oplock_break Error status=",hex(smb['Status'])
            else:
                oplock_breakResponse   = SMBCommand(smb['Data'][0])
                data = oplock_break.oplock_break_Response_Structure(oplock_breakResponse,fileInfo)
            return smb['Status']

