# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id: ntlm.py,v 1.2 2006/05/23 21:19:25 gera Exp $
#


#!/usr/bin/env python

from structure import Structure
try:
    from Crypto.Cipher import DES
    from Crypto.Hash import MD4
    POW = None
except Exception:
    try:
        import POW
    except Exception:
        pass

NTLM_AUTH_NONE          = 1
NTLM_AUTH_CONNECT       = 2
NTLM_AUTH_CALL          = 3
NTLM_AUTH_PKT           = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY   = 6

NTLMSSP_KEY_56       = 0x80000000
NTLMSSP_KEY_EXCHANGE = 0x40000000
NTLMSSP_KEY_128      = 0x20000000
# NTLMSSP_           = 0x10000000
# NTLMSSP_           = 0x08000000
# NTLMSSP_           = 0x04000000
# NTLMSSP_           = 0x02000000
# NTLMSSP_           = 0x01000000
NTLMSSP_TARGET_INFO  = 0x00800000
# NTLMSSP_           = 0x00400000
# NTLMSSP_           = 0x00200000
# NTLMSSP_           = 0x00100000
NTLMSSP_NTLM2_KEY    = 0x00080000
NTLMSSP_CHALL_NOT_NT = 0x00040000
NTLMSSP_CHALL_ACCEPT = 0x00020000
NTLMSSP_CHALL_INIT   = 0x00010000
NTLMSSP_ALWAYS_SIGN  = 0x00008000       # forces the other end to sign packets
NTLMSSP_LOCAL_CALL   = 0x00004000
NTLMSSP_WORKSTATION  = 0x00002000
NTLMSSP_DOMAIN       = 0x00001000
# NTLMSSP_           = 0x00000800
# NTLMSSP_           = 0x00000400
NTLMSSP_NTLM_KEY     = 0x00000200
NTLMSSP_NETWARE      = 0x00000100
NTLMSSP_LM_KEY       = 0x00000080
NTLMSSP_DATAGRAM     = 0x00000040
NTLMSSP_SEAL         = 0x00000020
NTLMSSP_SIGN         = 0x00000010       # means packet is signed, if verifier is wrong it fails
# NTLMSSP_           = 0x00000008
NTLMSSP_TARGET       = 0x00000004
NTLMSSP_OEM          = 0x00000002
NTLMSSP_UNICODE      = 0x00000001

class NTLMAuthHeader(Structure):
    commonHdr = (
#        ('auth_type', 'B=10'),
#        ('auth_level','B'),
#        ('auth_pad_len','B=0'),
#        ('auth_rsvrd','"\x00'),
#        ('auth_ctx_id','<L=747920'),
        )
    structure = (
#        ('data',':'),
    )

class NTLMAuthNegotiate(NTLMAuthHeader):
    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=1'),
        ('flags','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_maxlen','<H-host_name'),
        ('host_offset','<L'),
        ('host_name',':'),
        ('domain_name',':'))

    def __init__(self):
        NTLMAuthHeader.__init__(self)
        self['flags']= (
               NTLMSSP_KEY_128     |
               NTLMSSP_KEY_EXCHANGE|
               # NTLMSSP_LM_KEY      |
               NTLMSSP_NTLM_KEY    |
               NTLMSSP_UNICODE     |
               # NTLMSSP_ALWAYS_SIGN |
               NTLMSSP_SIGN        |
               NTLMSSP_SEAL        |
               # NTLMSSP_TARGET      |
               0)
        self['host_name']=''
        self['domain_name']=''

    def __str__(self):
        self['host_offset']=32
        self['domain_offset']=32+len(self['host_name'])
        return NTLMAuthHeader.__str__(self)

class NTLMAuthChallenge(NTLMAuthHeader):
    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=2'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('flags','<L'),
        ('challenge','8s'),
        ('reserved','"\x00\x00\x00\x00\x00\x00\x00\x00'),
        ('domain_name',':'))

class NTLMAuthChallengeResponse(NTLMAuthHeader):
    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=3'),
        ('lanman_len','<H-lanman'),
        ('lanman_max_len','<H-lanman'),
        ('lanman_offset','<L'),
        ('ntlm_len','<H-ntlm'),
        ('ntlm_max_len','<H-ntlm'),
        ('ntlm_offset','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('user_len','<H-user_name'),
        ('user_max_len','<H-user_name'),
        ('user_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_max_len','<H-host_name'),
        ('host_offset','<L'),
        ('session_key_len','<H-session_key'),
        ('session_key_max_len','<H-session_key'),
        ('session_key_offset','<L'),
        ('flags','<L'),
        ('domain_name',':'),
        ('user_name',':'),
        ('host_name',':'),
        ('lanman',':'),
        ('ntlm',':'),
        ('session_key',':'))

    def __init__(self, username, password, challenge):
        NTLMAuthHeader.__init__(self)
        self['session_key']=''
        self['user_name']=username.encode('utf-16le')
        self['domain_name']='' #"CLON".encode('utf-16le')
        self['host_name']='' #"BETS".encode('utf-16le')
        self['flags'] = (   #authResp['flags']
                # we think (beto & gera) that his flags force a memory conten leakage when a windows 2000 answers using uninitializaed verifiers
           NTLMSSP_KEY_128     |
           NTLMSSP_KEY_EXCHANGE|
           # NTLMSSP_LM_KEY      |
           NTLMSSP_NTLM_KEY    |
           NTLMSSP_UNICODE     |
           # NTLMSSP_ALWAYS_SIGN |
           NTLMSSP_SIGN        |
           NTLMSSP_SEAL        |
           # NTLMSSP_TARGET      |
           0)
        # Here we do the stuff
        if username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            self['lanman']=get_ntlmv1_response(lmhash, challenge)
            self['ntlm']=get_ntlmv1_response(nthash, challenge)    # This is not used for LM_KEY nor NTLM_KEY
        else:
            self['lanman'] = ''
            self['ntlm'] = ''
            if not self['host_name']:
                self['host_name'] = 'NULL'.encode('utf-16le')      # for NULL session there must be a hostname

    def __str__(self):
        self['domain_offset']=64
        self['user_offset']=64+len(self['domain_name'])
        self['host_offset']=self['user_offset']+len(self['user_name'])
        self['lanman_offset']=self['host_offset']+len(self['host_name'])
        self['ntlm_offset']=self['lanman_offset']+len(self['lanman'])
        self['session_key_offset']=self['ntlm_offset']+len(self['ntlm'])
        return NTLMAuthHeader.__str__(self)

class ImpacketStructure(Structure):
    def set_parent(self, other):
        self.parent = other

    def get_packet(self):
        return str(self)

    def get_size(self):
        return len(self)

class NTLMAuthVerifier(NTLMAuthHeader):
    structure = (
        ('version','<L=1'),
        ('data','12s'),
        # ('_zero','<L=0'),
        # ('crc','<L=0'),
        # ('sequence','<L=0'),
    )

KNOWN_DES_INPUT = "KGS!@#$%"

def __expand_DES_key( key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
    key  = key[:7]
    key += '\x00'*(7-len(key))
    s = chr(((ord(key[0]) >> 1) & 0x7f) << 1)
    s = s + chr(((ord(key[0]) & 0x01) << 6 | ((ord(key[1]) >> 2) & 0x3f)) << 1)
    s = s + chr(((ord(key[1]) & 0x03) << 5 | ((ord(key[2]) >> 3) & 0x1f)) << 1)
    s = s + chr(((ord(key[2]) & 0x07) << 4 | ((ord(key[3]) >> 4) & 0x0f)) << 1)
    s = s + chr(((ord(key[3]) & 0x0f) << 3 | ((ord(key[4]) >> 5) & 0x07)) << 1)
    s = s + chr(((ord(key[4]) & 0x1f) << 2 | ((ord(key[5]) >> 6) & 0x03)) << 1)
    s = s + chr(((ord(key[5]) & 0x3f) << 1 | ((ord(key[6]) >> 7) & 0x01)) << 1)
    s = s + chr((ord(key[6]) & 0x7f) << 1)
    return s

def __DES_block(key, msg):
    if POW:
        cipher = POW.Symmetric(POW.DES_ECB)
        cipher.encryptInit(__expand_DES_key(key))
        return cipher.update(msg)
    else:
        cipher = DES.new(__expand_DES_key(key),DES.MODE_ECB)
        return cipher.encrypt(msg)

def ntlmssp_DES_encrypt(key, challenge):
    answer  = __DES_block(key[:7], challenge)
    answer += __DES_block(key[7:14], challenge)
    answer += __DES_block(key[14:], challenge)
    return answer

def compute_lmhash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = password.upper()
    lmhash  = __DES_block(password[:7], KNOWN_DES_INPUT)
    lmhash += __DES_block(password[7:14], KNOWN_DES_INPUT)
    return lmhash

def compute_nthash(isunicode, password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    if ( isunicode ):
        password = unicode(password).encode('utf_16le')
    if POW:
        hash = POW.Digest(POW.MD4_DIGEST)
    else:
        hash = MD4.new()
    hash.update(password)
    return hash.digest()

def get_ntlmv1_response(key, challenge):
    return ntlmssp_DES_encrypt(key, challenge)

##################################################################################################

import struct
import base64
import string
import des
import hashlib
import hmac
import random
from socket import gethostname

NTLM_NegotiateUnicode                =  0x00000001
NTLM_NegotiateOEM                    =  0x00000002
NTLM_RequestTarget                   =  0x00000004
NTLM_Unknown9                        =  0x00000008
NTLM_NegotiateSign                   =  0x00000010
NTLM_NegotiateSeal                   =  0x00000020
NTLM_NegotiateDatagram               =  0x00000040
NTLM_NegotiateLanManagerKey          =  0x00000080
NTLM_Unknown8                        =  0x00000100
NTLM_NegotiateNTLM                   =  0x00000200
NTLM_NegotiateNTOnly                 =  0x00000400
NTLM_Anonymous                       =  0x00000800
NTLM_NegotiateOemDomainSupplied      =  0x00001000
NTLM_NegotiateOemWorkstationSupplied =  0x00002000
NTLM_Unknown6                        =  0x00004000
NTLM_NegotiateAlwaysSign             =  0x00008000
NTLM_TargetTypeDomain                =  0x00010000
NTLM_TargetTypeServer                =  0x00020000
NTLM_TargetTypeShare                 =  0x00040000
NTLM_NegotiateExtendedSecurity       =  0x00080000
NTLM_NegotiateIdentify               =  0x00100000
NTLM_Unknown5                        =  0x00200000
NTLM_RequestNonNTSessionKey          =  0x00400000
NTLM_NegotiateTargetInfo             =  0x00800000
NTLM_Unknown4                        =  0x01000000
NTLM_NegotiateVersion                =  0x02000000
NTLM_Unknown3                        =  0x04000000
NTLM_Unknown2                        =  0x08000000
NTLM_Unknown1                        =  0x10000000
NTLM_Negotiate128                    =  0x20000000
NTLM_NegotiateKeyExchange            =  0x40000000
NTLM_Negotiate56                     =  0x80000000

# we send these flags with our type 1 message
NTLM_TYPE1_FLAGS = (NTLM_NegotiateUnicode | \
                    NTLM_NegotiateOEM | \
                    NTLM_RequestTarget | \
                    NTLM_NegotiateNTLM | \
                    NTLM_NegotiateOemDomainSupplied | \
                    NTLM_NegotiateOemWorkstationSupplied | \
                    NTLM_NegotiateAlwaysSign | \
                    NTLM_NegotiateExtendedSecurity | \
                    NTLM_NegotiateVersion | \
                    NTLM_Negotiate128 | \
                    NTLM_Negotiate56 )
NTLM_TYPE2_FLAGS = (NTLM_NegotiateUnicode | \
                    NTLM_RequestTarget | \
                    NTLM_NegotiateNTLM | \
                    NTLM_NegotiateAlwaysSign | \
                    NTLM_NegotiateExtendedSecurity | \
                    NTLM_NegotiateTargetInfo | \
                    NTLM_NegotiateVersion | \
                    NTLM_Negotiate128 | \
                    NTLM_Negotiate56)

NTLM_MsvAvEOL             = 0 # Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
NTLM_MsvAvNbComputerName  = 1 # The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvNbDomainName    = 2 # The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
NTLM_MsvAvDnsComputerName = 3 # The server's Active Directory DNS computer name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsDomainName   = 4 # The server's Active Directory DNS domain name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvDnsTreeName     = 5 # The server's Active Directory (AD) DNS forest tree name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MsvAvFlags           = 6 # A field containing a 32-bit value indicating server or client configuration. 0x00000001: indicates to the client that the account authentication is constrained. 0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
NTLM_MsvAvTimestamp       = 7 # A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<12>
NTLM_MsAvRestrictions     = 8 #A Restriction_Encoding structure (section 2.2.2.2). The Value field contains a structure representing the integrity level of the security principal, as well as a MachineID created at computer startup to identify the calling machine. <13>


"""
utility functions for Microsoft NTLM authentication

References:
[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf

[MS-NTHT]: NTLM Over HTTP Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf

Cntlm Authentication Proxy
http://cntlm.awk.cz/

NTLM Authorization Proxy Server
http://sourceforge.net/projects/ntlmaps/

Optimized Attack for NTLM2 Session Response
http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf
"""
def dump_NegotiateFlags(NegotiateFlags):
    if NegotiateFlags & NTLM_NegotiateUnicode:
        print "NTLM_NegotiateUnicode set"
    if NegotiateFlags & NTLM_NegotiateOEM:
        print "NTLM_NegotiateOEM set"                  
    if NegotiateFlags & NTLM_RequestTarget:
        print "NTLM_RequestTarget set"                  
    if NegotiateFlags & NTLM_Unknown9:
        print "NTLM_Unknown9 set"                      
    if NegotiateFlags & NTLM_NegotiateSign:
        print "NTLM_NegotiateSign set"                  
    if NegotiateFlags & NTLM_NegotiateSeal:
        print "NTLM_NegotiateSeal set"                  
    if NegotiateFlags & NTLM_NegotiateDatagram:
        print "NTLM_NegotiateDatagram set"              
    if NegotiateFlags & NTLM_NegotiateLanManagerKey:
        print "NTLM_NegotiateLanManagerKey set"
    if NegotiateFlags & NTLM_Unknown8:
        print "NTLM_Unknown8 set"                      
    if NegotiateFlags & NTLM_NegotiateNTLM:
        print "NTLM_NegotiateNTLM set"                  
    if NegotiateFlags & NTLM_NegotiateNTOnly:
        print "NTLM_NegotiateNTOnly set"                
    if NegotiateFlags & NTLM_Anonymous:
        print "NTLM_Anonymous set"                      
    if NegotiateFlags & NTLM_NegotiateOemDomainSupplied:
        print "NTLM_NegotiateOemDomainSupplied set"    
    if NegotiateFlags & NTLM_NegotiateOemWorkstationSupplied:
        print "NTLM_NegotiateOemWorkstationSupplied set"
    if NegotiateFlags & NTLM_Unknown6:
        print "NTLM_Unknown6 set"                      
    if NegotiateFlags & NTLM_NegotiateAlwaysSign:
        print "NTLM_NegotiateAlwaysSign set"            
    if NegotiateFlags & NTLM_TargetTypeDomain:
        print "NTLM_TargetTypeDomain set"              
    if NegotiateFlags & NTLM_TargetTypeServer:
        print "NTLM_TargetTypeServer set"              
    if NegotiateFlags & NTLM_TargetTypeShare:
        print "NTLM_TargetTypeShare set"                
    if NegotiateFlags & NTLM_NegotiateExtendedSecurity:
        print "NTLM_NegotiateExtendedSecurity set"      
    if NegotiateFlags & NTLM_NegotiateIdentify:
        print "NTLM_NegotiateIdentify set"              
    if NegotiateFlags & NTLM_Unknown5:
        print "NTLM_Unknown5 set"                      
    if NegotiateFlags & NTLM_RequestNonNTSessionKey:
        print "NTLM_RequestNonNTSessionKey set"        
    if NegotiateFlags & NTLM_NegotiateTargetInfo:
        print "NTLM_NegotiateTargetInfo set"            
    if NegotiateFlags & NTLM_Unknown4:
        print "NTLM_Unknown4 set"                      
    if NegotiateFlags & NTLM_NegotiateVersion:
        print "NTLM_NegotiateVersion set"              
    if NegotiateFlags & NTLM_Unknown3:
        print "NTLM_Unknown3 set"                      
    if NegotiateFlags & NTLM_Unknown2:
        print "NTLM_Unknown2 set"                      
    if NegotiateFlags & NTLM_Unknown1:
        print "NTLM_Unknown1 set"                      
    if NegotiateFlags & NTLM_Negotiate128:
        print "NTLM_Negotiate128 set"                  
    if NegotiateFlags & NTLM_NegotiateKeyExchange:
        print "NTLM_NegotiateKeyExchange set"          
    if NegotiateFlags & NTLM_Negotiate56:
        print "NTLM_Negotiate56 set"                    

def create_NTLM_NEGOTIATE_MESSAGE(user):
    BODY_LENGTH = 40
    Payload_start = BODY_LENGTH # in bytes
    protocol = 'NTLMSSP\0'    #name        
   
    type = struct.pack('<I',1) #type 1
   
    flags =  struct.pack('<I', NTLM_TYPE1_FLAGS)
    Workstation = gethostname().upper().encode('ascii')
    user_parts = user.split('\\', 1)
    DomainName = user_parts[0].upper().encode('ascii')
    EncryptedRandomSessionKey = ""
   
   
    WorkstationLen = struct.pack('<H', len(Workstation))
    WorkstationMaxLen = struct.pack('<H', len(Workstation))
    WorkstationBufferOffset = struct.pack('<I', Payload_start)
    Payload_start += len(Workstation)
    DomainNameLen = struct.pack('<H', len(DomainName))
    DomainNameMaxLen = struct.pack('<H', len(DomainName))
    DomainNameBufferOffset = struct.pack('<I',Payload_start)
    Payload_start += len(DomainName)
    ProductMajorVersion = struct.pack('<B', 5)
    ProductMinorVersion = struct.pack('<B', 1)
    ProductBuild = struct.pack('<H', 2600)
    VersionReserved1 = struct.pack('<B', 0)
    VersionReserved2 = struct.pack('<B', 0)
    VersionReserved3 = struct.pack('<B', 0)
    NTLMRevisionCurrent = struct.pack('<B', 15)
#    print Workstation,user_parts,DomainName
    reserved1 = struct.pack('<Q', 0)
    reserved2 = struct.pack('<Q', 0)
    reserved3 = struct.pack('<Q', 0)
   
    msg1 = protocol + type + flags
#    msg1 = protocol + type + flags + \
#            DomainNameLen + DomainNameMaxLen + DomainNameBufferOffset + \
#            WorkstationLen + WorkstationMaxLen + WorkstationBufferOffset + \
#            ProductMajorVersion + ProductMinorVersion + ProductBuild + \
#            VersionReserved1 + VersionReserved2 + VersionReserved3 + NTLMRevisionCurrent
#    assert BODY_LENGTH==len(msg1), "BODY_LENGTH: %d != msg1: %d" % (BODY_LENGTH,len(msg1))
#    msg1 += Workstation + DomainName

    msg1 += reserved1 + reserved2 + reserved3
#    print len(msg1)
#    msg1 = base64.encodestring(msg1)
#    msg1 = string.replace(msg1, '\n', '')
    return msg1
   
def parse_NTLM_CHALLENGE_MESSAGE(msg2):
    ""
    msg2 = base64.decodestring(msg2)
    Signature = msg2[0:8]
    msg_type = struct.unpack("<I",msg2[8:12])[0]
    assert(msg_type==2)
    TargetNameLen = struct.unpack("<H",msg2[12:14])[0]
    TargetNameMaxLen = struct.unpack("<H",msg2[14:16])[0]
    TargetNameOffset = struct.unpack("<I",msg2[16:20])[0]
    TargetName = msg2[TargetNameOffset:TargetNameOffset+TargetNameMaxLen]
    NegotiateFlags = struct.unpack("<I",msg2[20:24])[0]
    ServerChallenge = msg2[24:32]
    Reserved = msg2[32:40]
    TargetInfoLen = struct.unpack("<H",msg2[40:42])[0]
    TargetInfoMaxLen = struct.unpack("<H",msg2[42:44])[0]
    TargetInfoOffset = struct.unpack("<I",msg2[44:48])[0]
    TargetInfo = msg2[TargetInfoOffset:TargetInfoOffset+TargetInfoLen]
    i=0
    TimeStamp = '\0'*8
    while(i<TargetInfoLen):
        AvId = struct.unpack("<H",TargetInfo[i:i+2])[0]
        AvLen = struct.unpack("<H",TargetInfo[i+2:i+4])[0]
        AvValue = TargetInfo[i+4:i+4+AvLen]
        i = i+4+AvLen
        if AvId == NTLM_MsvAvTimestamp:
            TimeStamp = AvValue
        #~ print AvId, AvValue.decode('utf-16')
    return (ServerChallenge, NegotiateFlags)

def create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, domain, password, NegotiateFlags):
    ""
    is_unicode  = NegotiateFlags & NTLM_NegotiateUnicode
    is_NegotiateExtendedSecurity = NegotiateFlags & NTLM_NegotiateExtendedSecurity
   
    flags =  struct.pack('<I',NTLM_TYPE2_FLAGS)

    BODY_LENGTH = 72  #+ 16
    Payload_start = BODY_LENGTH # in bytes

    Workstation = gethostname().upper()
    DomainName = domain.upper()
    UserName = user
    EncryptedRandomSessionKey = "12345678"
    if is_unicode:
        Workstation = Workstation.encode('utf-16-le')
        DomainName = DomainName.encode('utf-16-le')
        UserName = UserName.encode('utf-16-le')
        EncryptedRandomSessionKey = EncryptedRandomSessionKey.encode('utf-16-le')
    LmChallengeResponse = calc_resp(create_LM_hashed_password_v1(password), nonce)
    NtChallengeResponse = calc_resp(create_NT_hashed_password_v1(password), nonce)
   
    if is_NegotiateExtendedSecurity:
        pwhash = create_NT_hashed_password_v1(password, UserName, DomainName)
        ClientChallenge = ""
        for i in range(8):
           ClientChallenge+= chr(random.getrandbits(8))
        (NtChallengeResponse, LmChallengeResponse) = ntlm2sr_calc_resp(pwhash, nonce, ClientChallenge) #='\x39 e3 f4 cd 59 c5 d8 60')
    Signature = 'NTLMSSP\0'          
    MessageType = struct.pack('<I',3)  #type 3
   
    DomainNameLen = struct.pack('<H', len(DomainName))
    DomainNameMaxLen = struct.pack('<H', len(DomainName))
    DomainNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(DomainName)
   
    UserNameLen = struct.pack('<H', len(UserName))
    UserNameMaxLen = struct.pack('<H', len(UserName))
    UserNameOffset = struct.pack('<I', Payload_start)
    Payload_start += len(UserName)
   
    WorkstationLen = struct.pack('<H', len(Workstation))
    WorkstationMaxLen = struct.pack('<H', len(Workstation))
    WorkstationOffset = struct.pack('<I', Payload_start)
    Payload_start += len(Workstation)
   
   
    LmChallengeResponseLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseMaxLen = struct.pack('<H', len(LmChallengeResponse))
    LmChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(LmChallengeResponse)
   
    NtChallengeResponseLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseMaxLen = struct.pack('<H', len(NtChallengeResponse))
    NtChallengeResponseOffset = struct.pack('<I', Payload_start)
    Payload_start += len(NtChallengeResponse)
   
    EncryptedRandomSessionKeyLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyMaxLen = struct.pack('<H', len(EncryptedRandomSessionKey))
    EncryptedRandomSessionKeyOffset = struct.pack('<I',Payload_start)
    Payload_start +=  len(EncryptedRandomSessionKey)
    NegotiateFlags = flags
   
    ProductMajorVersion = struct.pack('<B', 6) #windows xp it is 5
    ProductMinorVersion = struct.pack('<B', 0) #windows7 it is 1
    ProductBuild = struct.pack('<H', 2600)
    VersionReserved1 = struct.pack('<B', 0)
    VersionReserved2 = struct.pack('<B', 0)
    VersionReserved3 = struct.pack('<B', 0)
    NTLMRevisionCurrent = struct.pack('<B', 15)
   
    MIC = struct.pack('<IIII',0,0,0,0)
#    MIC = struct.pack('<BBBBBBBBBBBBBBBB',0x37,0xF2,0xF0,0x34,0xD2,0x8E,0x0,0x61,0xAC,0x12,0xDD,0x0e,0x9d,0x5d,0xfe,0xb8)
    msg3 = Signature + MessageType + \
            LmChallengeResponseLen + LmChallengeResponseMaxLen + LmChallengeResponseOffset + \
            NtChallengeResponseLen + NtChallengeResponseMaxLen + NtChallengeResponseOffset + \
            DomainNameLen + DomainNameMaxLen + DomainNameOffset + \
            UserNameLen + UserNameMaxLen + UserNameOffset + \
            WorkstationLen + WorkstationMaxLen + WorkstationOffset + \
            EncryptedRandomSessionKeyLen + EncryptedRandomSessionKeyMaxLen + EncryptedRandomSessionKeyOffset + \
            NegotiateFlags + \
            ProductMajorVersion + ProductMinorVersion + ProductBuild + \
            VersionReserved1 + VersionReserved2 + VersionReserved3 + NTLMRevisionCurrent + MIC
#    assert BODY_LENGTH==len(msg3), "BODY_LENGTH: %d != msg3: %d" % (BODY_LENGTH,len(msg3))
    Payload = DomainName + UserName + Workstation + LmChallengeResponse + NtChallengeResponse + EncryptedRandomSessionKey
    msg3 += Payload
#    msg3 = base64.encodestring(msg3)
#    msg3 = string.replace(msg3, '\n', '')
    return msg3
           
def calc_resp(password_hash, server_challenge):
    """calc_resp generates the LM response given a 16-byte password hash and the
        challenge from the Type-2 message.
        @param password_hash
            16-byte password hash
        @param server_challenge
            8-byte challenge from Type-2 message
        returns
            24-byte buffer to contain the LM response upon return
    """
    # padding with zeros to make the hash 21 bytes long
    password_hash = password_hash + '\0' * (21 - len(password_hash))
    res = ''
    dobj = des.DES(password_hash[0:7])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = des.DES(password_hash[7:14])
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = des.DES(password_hash[14:21])
    res = res + dobj.encrypt(server_challenge[0:8])
    return res
   
def ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge='\xaa'*8, Time='\0'*8):
    LmChallengeResponse = hmac.new(ResponseKeyLM, ServerChallenge+ClientChallenge).digest() + ClientChallenge
   
    Responserversion = '\x01'
    HiResponserversion = '\x01'
    temp = Responserversion + HiResponserversion + '\0'*6 + Time + ClientChallenge + '\0'*4 + ServerChallenge + '\0'*4
    NTProofStr  = hmac.new(ResponseKeyNT, ServerChallenge + temp).digest()
    NtChallengeResponse = NTProofStr + temp
   
    SessionBaseKey = hmac.new(ResponseKeyNT, NTProofStr).digest()
    return (NtChallengeResponse, LmChallengeResponse)

def ntlm2sr_calc_resp(ResponseKeyNT, ServerChallenge, ClientChallenge='\xaa'*8):
    import hashlib
    LmChallengeResponse = ClientChallenge + '\0'*16
    sess = hashlib.md5(ServerChallenge+ClientChallenge).digest()
    NtChallengeResponse = calc_resp(ResponseKeyNT, sess[0:8])
    return (NtChallengeResponse, LmChallengeResponse)

def create_LM_hashed_password_v1(passwd):
    "setup LanManager password"
    "create LanManager hashed password"
   
    # fix the password length to 14 bytes
    passwd = string.upper(passwd)
    lm_pw = passwd + '\0' * (14 - len(passwd))
    lm_pw = passwd[0:14]

    # do hash
    magic_str = "KGS!@#$%" # page 57 in [MS-NLMP]

    res = ''
    dobj = des.DES(lm_pw[0:7])
    res = res + dobj.encrypt(magic_str)

    dobj = des.DES(lm_pw[7:14])
    res = res + dobj.encrypt(magic_str)

    return res
   
def create_NT_hashed_password_v1(passwd, user=None, domain=None):
    "create NT hashed password"
    digest = hashlib.new('md4', passwd.encode('utf-16le')).digest()
    return digest

def create_NT_hashed_password_v2(passwd, user, domain):
    "create NT hashed password"
    digest = create_NT_hashed_password_v1(passwd)
   
    return hmac.new(digest, (user.upper()+domain).encode('utf-16le')).digest()
    return digest
   
def create_sessionbasekey(password):
    return hashlib.new('md4', create_NT_hashed_password_v1(password)).digest()

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    bytes = []
    hexStr = hexStr.replace(" ", "")
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( bytes )

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    return ' '.join( [ "%02X" % ord(x) for x in byteStr ] )