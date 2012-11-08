#!/usr/bin/env python

import string

SMB_HEADER_LEN = 0x20
TRANS2_RESP_LEN = 20

# Shared Device Type
SHARED_DISK = 0x00
SHARED_DEVICE = 0x02
SHARED_IPC = 0x03

# SMB Command Codes
SMB_NONE                    = 0xff
SMB_CREATE_DIR              = 0x00
SMB_DELETE_DIR              = 0x01
SMB_OPEN                    = 0x02
SMB_CREATE                  = 0x03
SMB_CLOSE                   = 0x04
SMB_FLUSH                   = 0x05
SMB_DELETE                  = 0x06
SMB_RENAME                  = 0x07
SMB_QUERY_INFORMATION       = 0x08
SMB_SET_INFORMATION         = 0x09
SMB_READ                    = 0x0a
SMB_WRITE                   = 0x0b
SMB_LOCK_BYTE_RANGE         = 0x0C
SMB_UNLOCK_BYTE_RANGE       = 0x0D
SMB_CREATE_TEMPORARY        = 0x0E
SMB_CREATE_NEW              = 0x0F
SMB_CHECK_DIR               = 0x10
SMB_SEEK_FILE               = 0x12
SMB_LOCK_AND_READ           = 0x13
SMB_WRITE_AND_UNLOCK        = 0x14
SMB_READ_RAW                = 0x1a
SMB_WRITE_RAW               = 0x1d
SMB_LOCKING_ANDX            = 0x24
SMB_TRANSACTION             = 0x25
SMB_ECHO                    = 0x2b
SMB_OPEN_ANDX               = 0x2d
SMB_READ_ANDX               = 0x2e
SMB_WRITE_ANDX              = 0x2f
SMB_TREE_DISCONNECT         = 0x71
SMB_NEGOTIATE               = 0x72
SMB_SESSION_SETUP_ANDX      = 0x73
SMB_LOGOFF                  = 0x74
SMB_TREE_CONNECT_ANDX       = 0x75
SMB_NT_CREATE_ANDX          = 0xA2
SMB_WRITE_AND_CLOSE         = 0x2c
SMB_QUERY_INFORMATION_DISK  = 0x80
SMB_CLOSE_AND_TREE_DISC     = 0x31
SMB_MOVE                    = 0x2A
SMB_ECHO                    = 0x2B
SMB_COPY                    = 0x29
SMB_TRANSACTION2            = 0x32
SMB_FIND_CLOSE2             = 0x34


GEN_COMMAND_OFFSET	    = 0x11000

#Local command
SMB_GEN_CREATE_DIR             	= (GEN_COMMAND_OFFSET + 0)
SMB_GEN_DELETE_DIR		        = (GEN_COMMAND_OFFSET + 1)
SMB_GEN_OPEN			        = (GEN_COMMAND_OFFSET + 2)
SMB_GEN_CREATE			        = (GEN_COMMAND_OFFSET + 3)
SMB_GEN_CLOSE			        = (GEN_COMMAND_OFFSET + 4)
SMB_GEN_FLUSH			        = (GEN_COMMAND_OFFSET + 5)
SMB_GEN_DELETE			        = (GEN_COMMAND_OFFSET + 6)
SMB_GEN_RENAME			        = (GEN_COMMAND_OFFSET + 7)
SMB_GEN_QUERY_INFORMATION	   	= (GEN_COMMAND_OFFSET + 8)
SMB_GEN_SET_INFORMATION		   	= (GEN_COMMAND_OFFSET + 9)
SMB_GEN_READ			        = (GEN_COMMAND_OFFSET + 0xa)
SMB_GEN_WRITE			        = (GEN_COMMAND_OFFSET + 0xb)
SMB_GEN_LOCK_BYTE_RANGE		    = (GEN_COMMAND_OFFSET + 0xc)
SMB_GEN_UNLOCK_BYTE_RANGE	   	= (GEN_COMMAND_OFFSET + 0xd)
SMB_GEN_CREATE_TEMPORARY	    = (GEN_COMMAND_OFFSET + 0xe)
SMB_GEN_CREATE_NEW		        = (GEN_COMMAND_OFFSET + 0xf)
SMB_GEN_CHECK_DIR		        = (GEN_COMMAND_OFFSET + 0x10)
SMB_GEN_CHANGE_DIR             	= (GEN_COMMAND_OFFSET + 0x11)
SMB_GEN_LOCKING_ANDX            = (GEN_COMMAND_OFFSET + 0x12)


# Client customized commands, does not generate CIFS packets
SMB_GEN_WAIT				    = (GEN_COMMAND_OFFSET + 0x20)
SMB_GEN_OPLOCK_BREAK			= (GEN_COMMAND_OFFSET + 0x21)
SMB_GEN_USE_SHARE				= (GEN_COMMAND_OFFSET + 0x22)

NT_TRANSACT_CREATE               =  1     #File open/create
NT_TRANSACT_IOCTL                =  2     #Device IOCTL
NT_TRANSACT_SET_SECURITY_DESC    =  3     #Set security descriptor
NT_TRANSACT_NOTIFY_CHANGE        =  4     #Start directory watch
NT_TRANSACT_RENAME               =  5     #Reserved (Handle-based rename)
NT_TRANSACT_QUERY_SECURITY_DESC  =  6     #Retrieve security
                                          #descriptor info


#Trans2 subcommands list
TRANS2_OPEN2                    = 0x00  #Create file with extended attributes
TRANS2_FIND_FIRST2              = 0x01  #Begin search for files
TRANS2_FIND_NEXT2               = 0x02  #Resume search for files
TRANS2_QUERY_FS_INFORMATION     = 0x03  #Get file system information
TRANS2_RESERVED                 = 0x04  #Reserved
TRANS2_QUERY_PATH_INFORMATION   = 0x05  #Get information about a named
                                      #  file or directory
TRANS2_SET_PATH_INFORMATION     = 0x06  #Set information about a named
                                      #  file or directory
TRANS2_QUERY_FILE_INFORMATION   = 0x07  #Get information about a
                                      #  handle
TRANS2_SET_FILE_INFORMATION     = 0x08  #Set information by handle
TRANS2_FSCTL                    = 0x09  #Not implemented by NT server
TRANS2_IOCTL2                   = 0x0A  #Not implemented by NT server
TRANS2_FIND_NOTIFY_FIRST        = 0x0B  #Not implemented by NT server
TRANS2_FIND_NOTIFY_NEXT         = 0x0C  #Not implemented by NT server
TRANS2_CREATE_DIRECTORY         = 0x0D  #Create directory with
                                      #  extended attributes
TRANS2_SESSION_SETUP            = 0x0E  #Session setup with extended
                                      #  security information
TRANS2_GET_DFS_REFERRAL         = 0x10  #Get a DFS referral
TRANS2_REPORT_DFS_INCONSISTENCY = 0x11  #Report a DFS knowledge
                                      #  inconsistency



#TRANS2_QUERY_FS_INFORMATION level of interest
SMB_INFO_ALLOCATION            = 0x001
SMB_INFO_VOLUME                = 0x002
SMB_QUERY_FS_VOLUME_INFO       = 0x102
SMB_QUERY_FS_SIZE_INFO         = 0x103
SMB_QUERY_FS_DEVICE_INFO       = 0x104
SMB_QUERY_FS_ATTRIBUTE_INFO    = 0x105
SMB_QUERY_FS_FULL_SIZE_INFO    = 0x107

g_queryfs_level_of_interest = [
                ['alloc', SMB_INFO_ALLOCATION],
                ['vol', SMB_INFO_VOLUME],
                ['fsvol', SMB_QUERY_FS_VOLUME_INFO],
                ['size',SMB_QUERY_FS_SIZE_INFO],
                ['device',SMB_QUERY_FS_DEVICE_INFO ],
                ['attrinfo',SMB_QUERY_FS_ATTRIBUTE_INFO ],
                ['fullsize',SMB_QUERY_FS_FULL_SIZE_INFO ],
           ]

def g_get_queryfs_loi_from_string(loistring):
	loi = -1
	for loipair in g_queryfs_level_of_interest:
		if ( cmp(loipair[0], loistring) == 0):
			return loipair[1]
	return loi

#TRANS2_QUERY_PATH_INFORMATION level of interest
SMB_INFO_STANDARD                = 1
SMB_INFO_QUERY_EA_SIZE           = 2
SMB_INFO_QUERY_EAS_FROM_LIST     = 3
SMB_INFO_QUERY_ALL_EAS           = 4
SMB_INFO_IS_NAME_VALID           = 6
SMB_QUERY_FILE_BASIC_INFO        = 0x101
SMB_QUERY_FILE_STANDARD_INFO     = 0x102
SMB_QUERY_FILE_EA_INFO           = 0x103
SMB_QUERY_FILE_NAME_INFO         = 0x104
SMB_QUERY_FILE_ALLOC_INFO        = 0x105
SMB_QUERY_FILE_EOF_INFO          = 0x106
SMB_QUERY_FILE_ALL_INFO          = 0x107
SMB_QUERY_FILE_ALT_NAME_INFO     = 0x108
SMB_QUERY_FILE_STREAM_INFO       = 0x109
SMB_QUERY_FILE_COMPRESSION_INFO  = 0x10B
SMB_QUERY_FILE_INTERNAL_INFO     = 1006
SMB_FILE_NETWORK_OPEN_INFORMATION = 1034

g_querypath_level_of_interest = [
                ['stdinfo', SMB_INFO_STANDARD],
                ['easize', SMB_INFO_QUERY_EA_SIZE],
                ['ealist', SMB_INFO_QUERY_EAS_FROM_LIST],
                ['alleas',SMB_INFO_QUERY_ALL_EAS ],
                ['isnamevalid',SMB_INFO_IS_NAME_VALID ],
                ['filebasicinfo',SMB_QUERY_FILE_BASIC_INFO ],
                ['filestdinfo',SMB_QUERY_FILE_STANDARD_INFO ],
                ['fileeainfo',SMB_QUERY_FILE_EA_INFO ],
                ['fninfo',SMB_QUERY_FILE_NAME_INFO ],
                ['fnallocinfo',SMB_QUERY_FILE_ALLOC_INFO ],
                ['fneofinfo',SMB_QUERY_FILE_EOF_INFO ],
                ['fnallinfo',SMB_QUERY_FILE_ALL_INFO ],
                ['fnaltnameinfo',SMB_QUERY_FILE_ALT_NAME_INFO ],
                ['streaminfo',SMB_QUERY_FILE_STREAM_INFO ],
                ['compressinfo',SMB_QUERY_FILE_COMPRESSION_INFO ],
                ['nwopeninfo',SMB_FILE_NETWORK_OPEN_INFORMATION ],
                ['fninternalinfo', SMB_QUERY_FILE_INTERNAL_INFO],
            ]

def g_get_querypath_loi_from_string(loistring):
	loi = -1
	for loipair in g_querypath_level_of_interest:
		if ( cmp(loipair[0], loistring) == 0):
			return loipair[1]
	return loi

#TRANS2_FIND_FIRST2 level of interest
## the below commented value are part of TRANS2_QUERY_PATH_INFORMATION
#SMB_INFO_STANDARD                  1
#SMB_INFO_QUERY_EA_SIZE             2
#SMB_INFO_QUERY_EAS_FROM_LIST       3
SMB_FIND_FILE_DIRECTORY_INFO       =	0x101
SMB_FIND_FILE_FULL_DIRECTORY_INFO  =	0x102
SMB_FIND_FILE_NAMES_INFO           =	0x103
SMB_FIND_FILE_BOTH_DIRECTORY_INFO  =	0x104
SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO =  0x105
SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO =  0x106

g_findfirst2_level_of_interest = [
                ['stdinfo', SMB_INFO_STANDARD],
                ['easize', SMB_INFO_QUERY_EA_SIZE],
                ['ealist', SMB_INFO_QUERY_EAS_FROM_LIST],
                ['filedirinfo', SMB_FIND_FILE_DIRECTORY_INFO],
                ['fulldirinfo', SMB_FIND_FILE_FULL_DIRECTORY_INFO],
                ['filenamesinfo', SMB_FIND_FILE_NAMES_INFO],
                ['bothfiledirinfo', SMB_FIND_FILE_BOTH_DIRECTORY_INFO],
                ['fileiddirinfo', SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO],
                ['bothfileiddirinfo', SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO],
            ]

def g_get_findfirst2_loi_from_string(loistring):
	loi = -1
	for loipair in g_findfirst2_level_of_interest:
		if ( cmp(loipair[0], loistring) == 0):
			return loipair[1]
	return loi

#TRANS2_SET_FILE_INFO
SMB_SET_FILE_BASIC_INFO          = 0x101
SMB_SET_FILE_DISPOSITION_INFO    = 0x3f5
SMB_SET_FILE_ALLOCATION_INFO     = 0x103
SMB_SET_FILE_END_OF_FILE_INFO    = 0x104

g_setfileinfo_level_of_interest = [
                ['stdinfo', SMB_NONE],
                ['easize', SMB_NONE],
                ['basicinfo', SMB_SET_FILE_BASIC_INFO, 9],
                ['delete', SMB_SET_FILE_DISPOSITION_INFO, 1],
                ['allocinfo', SMB_SET_FILE_ALLOCATION_INFO, 1],
                ['eofinfo', SMB_SET_FILE_END_OF_FILE_INFO, 1],
            ]

def g_get_setfile_loi_from_string(loistring):
	for loipair in g_setfileinfo_level_of_interest:
		if ( cmp(loipair[0], loistring) == 0):
			return loipair[1], loipair[2]
	return -1, 0



OPLOCK_LEVEL_NONE = 0
OPLOCK_LEVEL_SHARED = 1
OPLOCK_LEVEL_EXCLUSIVE = 2
OPLOCK_LEVEL_BATCH = 4

#LockType Flag Name            Value Description
#============================  ===== ================================

LOCKING_ANDX_SHARED_LOCK     = 0x01  #Read-only lock
LOCKING_ANDX_OPLOCK_RELEASE  = 0x02  #Oplock break notification
LOCKING_ANDX_CHANGE_LOCKTYPE = 0x04  #Change lock type
LOCKING_ANDX_CANCEL_LOCK     = 0x08  #Cancel outstanding request
LOCKING_ANDX_LARGE_FILE_LOCK = 0x10  #Large file locking format
LOCKING_ANDX_LARGE_FILE_UNLOCK = 0x80  #Large file locking format
LOCKING_ANDX_LOCK 	     = 0x20
LOCKING_ANDX_UNLOCK	     = 0x40

g_lockingandx_type = [
                ['lock',       		LOCKING_ANDX_LOCK],
                ['unlock',     		LOCKING_ANDX_UNLOCK],
                ['sharedlock', 		LOCKING_ANDX_SHARED_LOCK],
                ['oplockrelease', 	LOCKING_ANDX_OPLOCK_RELEASE],
                ['changelocktype',	LOCKING_ANDX_CHANGE_LOCKTYPE],
                ['lockcancel',		LOCKING_ANDX_CANCEL_LOCK ],
                ['largefile_lock',	LOCKING_ANDX_LARGE_FILE_LOCK],
                ['largefile_unlock',	LOCKING_ANDX_LARGE_FILE_UNLOCK],
            ]

def g_getlockingandx_from_string(loistring):
	for loipair in g_lockingandx_type:
		if ( cmp(loipair[0], loistring) == 0):
			return 1, loipair[1]
	return 0, 0

# Security Share Mode
SECURITY_SHARE_MASK = 0x01
SECURITY_SHARE_SHARE = 0x00
SECURITY_SHARE_USER = 0x01

# Security Auth Mode
SECURITY_AUTH_MASK = 0x02
SECURITY_AUTH_ENCRYPTED = 0x02
SECURITY_AUTH_PLAINTEXT = 0x00

# Raw Mode Mask (Good for dialect up to and including LANMAN2.1)
RAW_READ_MASK = 0x01
RAW_WRITE_MASK = 0x02

# Server Capabilities Mask for dialect NT LM 0.12
CAP_RAW_MODE 		= 0x00000001
CAP_MPX_MODE 		= 0x00000002
CAP_UNICODE 		= 0x00000004
CAP_LARGE_FILES 	= 0x00000008
CAP_NT_SMB 		= 0x00000010
CAP_REMOTE_RPC_API 	= 0x00000020
CAP_NT_STATUS_32 	= 0x00000040
CAP_DFS_RESOLVE 	= 0x00001000
CAP_UNIX_EXTENSION 	= 0x08000000
CAP_EXTENDED_SECURITY 	= 0x80000000
CAP_LEVEL_II_OPLOCKS 	= 0x0080
CAP_LOCK_AND_READ    	= 0x0100
CAP_NT_FIND       	= 0x0200
CAP_DFS 		= 0x1000
CAP_INFO_PASSTHRU	= 0x00002000
CAP_READX		= 0x00004000
CAP_WRITEX		= 0x00008000



# Flags1 Mask
FLAGS1_PATHCASELESS = 0x08
FLAGS1_CANONICALIZE = 0x10
FLAGS1_RECEIVE_BUF_POSTED = 0x40
FLAGS1_LOCK_AND_READ = 0x01

# Flags2 Mask
FLAGS2_UNICODE                      = 0x8000
FLAGS2_NT_32_STATUS_CODE            = 0x4000
FLAGS_EXE_ONLY_NO_READ              = 0x2000
FLAGS2_DFS_ENABLED                  = 0x1000
FLAGS2_SECURITY_NEGOTIATION         = 0x0800
FLAGS2_LONG_NAME_IN_REQUEST         = 0x0040
FLAGS2_SECURITY_SIGNATURE           = 0x0004
FLAGS2_EXTENDED_ATTRIBUTES          = 0x0002
FLAGS2_LONG_FILENAME_IN_RESPONSE    = 0x0001


#Authentication Modes
SMB_DIALECT_PC_NWK   = 0x0000
SMB_DIALECT_LANMAN10 = 0x0001
SMB_DIALECT_WWG      = 0x0002
SMB_DIALECT_LM12     = 0x0003
SMB_DIALECT_LM21     = 0x0004
SMB_DIALECT_NTLM12   = 0x0005
SMB_DIALECT_NTLM12_1 = 0x0006
SMB_DIALECT_SMB2     = 0x0007
SMB_DIALECT_UNK      = 0x0008

#Dialects
SMB_AUTH_MODE_LIST = [ ['SMB_DIALECT_PC_NWK',
                            '\x02PC NETWORK PROGRAM 1.0\x00'],
                       ['SMB_DIALECT_LANMAN10',
                            '\x02LANMAN1.0\x00'],
                       ['SMB_DIALECT_WWG',
                            '\x02Windows for workgroups 3.1\x00'],
                       ['SMB_DIALECT_LM12',
                            '\x02LM1.2X002\x00'],
                       ['SMB_DIALECT_LM21',
                            '\x02LANMAN2.1\x00'],
                       ['SMB_DIALECT_NTLM12',
                            '\x02NT LM 0.12\x00'],
                       ['SMB_DIALECT_NTLM12_1',
                            '\x02NT LANMAN 1.0\x00'],
                       ['SMB_DIALECT_SMB2',
                            '\x02SMB2.00\x00'],
                       ['SMB_DIALECT_UNK',
                            '\x02SMB_DIALECT_UNK\x00']
                     ]


SEEK_FILE_BEGINNING = 0
SEEK_FILE_CURRENT = 1
SEEK_FILE_END   = 2

def auth_mode_exist(auth):
    count = 0
    for authlist in SMB_AUTH_MODE_LIST:
        if authlist[0] == auth:
            return count
        count = count + 1

    return -1


# LIST OF SMB COMMANDS AS KEYWORDS IN TEST SCRIPT #
TEST_SCRIPT_KEYWORDS = [['test:', 		    SMB_NONE],
                        ['description:', 	SMB_NONE],
                        ['negotiate', 		SMB_NEGOTIATE],
                        ['session_setup',	SMB_SESSION_SETUP_ANDX],
                        ['logoff',		    SMB_LOGOFF],
                        ['echo',		    SMB_ECHO],
                        ['tree_connect',	SMB_TREE_CONNECT_ANDX],
                        ['nt_create',		SMB_NT_CREATE_ANDX],
                        ['nt_open',		    SMB_OPEN_ANDX],
                        ['closefile',		SMB_GEN_CLOSE],
                        ['tree_disconnect',	SMB_TREE_DISCONNECT],
                        ['nt_read',		    SMB_READ_ANDX],
                        ['nt_write',		SMB_WRITE_ANDX],
                        ['read',		    SMB_GEN_READ],
                        ['write',		    SMB_GEN_WRITE],
                        ['seekfile',		SMB_SEEK_FILE],
                        ['isdir',		    SMB_GEN_CHECK_DIR],
                        ['openfile',		SMB_GEN_OPEN],
                        ['flush', 		    SMB_GEN_FLUSH],
                        ['move', 		    SMB_MOVE],
                        ['copy', 		    SMB_COPY],
                        ['delete', 		    SMB_GEN_DELETE],
                        ['cd',			    SMB_GEN_CHANGE_DIR],
                        # close cwd, open directory
                        ['mkdir',		    SMB_GEN_CREATE_DIR],
                        ['rmdir',		    SMB_GEN_DELETE_DIR],
                        ['delete_dir',		SMB_GEN_DELETE_DIR],
                        ['rename',		    SMB_GEN_RENAME],
                        ['trans2', 		    SMB_TRANSACTION2],
                        ['getfsinfo', 		TRANS2_QUERY_FS_INFORMATION],
                        ['getfileinfo', 	TRANS2_QUERY_FILE_INFORMATION],
                        ['getpathinfo', 	TRANS2_QUERY_PATH_INFORMATION],
                        ['findfirst2',		TRANS2_FIND_FIRST2],
                        ['findclose2',		SMB_FIND_CLOSE2],
                        ['setfileinfo', 	TRANS2_SET_FILE_INFORMATION],
                        ['setpathinfo',		TRANS2_SET_PATH_INFORMATION],
                        ['trans2createdir', TRANS2_CREATE_DIRECTORY],
                        ['findfirst',		SMB_NONE],
                        ['findnext',		SMB_NONE],
                        ['lockandread', 	SMB_LOCK_AND_READ],
                        ['writeandunlock', 	SMB_WRITE_AND_UNLOCK],
                        ['lockbytes', 		SMB_LOCK_BYTE_RANGE],
                        ['unlockbytes', 	SMB_UNLOCK_BYTE_RANGE],
                        ['lockandx', 		SMB_GEN_LOCKING_ANDX],
                        ['wait', 		    SMB_GEN_WAIT],
                        ['useshare',        SMB_GEN_USE_SHARE],
                        ['waitforoplockbreak',   SMB_GEN_OPLOCK_BREAK],
                ]


# Extended attributes mask
ATTR_ARCHIVE = 0x020
ATTR_COMPRESSED = 0x800
ATTR_NORMAL = 0x080
ATTR_HIDDEN = 0x002
ATTR_READONLY = 0x001
ATTR_TEMPORARY = 0x100
ATTR_DIRECTORY = 0x010
ATTR_SYSTEM = 0x004

# Service Type
SERVICE_DISK = 'A:'
SERVICE_PRINTER = 'LPT1:'
SERVICE_IPC = 'IPC'
SERVICE_COMM = 'COMM'
SERVICE_ANY = '?????'

# Options values for SMB.stor_file and SMB.retr_file
SMB_O_CREAT = 0x10   # Create the file if file does not exists. Otherwise, operation fails.
SMB_O_EXCL = 0x00    # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
SMB_O_OPEN = 0x01    # Open the file if the file exists
SMB_O_TRUNC = 0x02   # Truncate the file if the file exists

# Share Access Mode
SMB_SHARE_COMPAT = 0x00
SMB_SHARE_DENY_EXCL = 0x10
SMB_SHARE_DENY_WRITE = 0x20
SMB_SHARE_DENY_READEXEC = 0x30
SMB_SHARE_DENY_NONE = 0x40
SMB_ACCESS_READ = 0x00
SMB_ACCESS_WRITE = 0x01
SMB_ACCESS_READWRITE = 0x02
SMB_ACCESS_EXEC = 0x03


