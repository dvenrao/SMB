#!/usr/bin/env python
import pdb
import time, sys
import thread,threading
import ConfigParser
import datetime
import codecs, platform
import socket, struct, os
import hashlib,unicodedata

##project based imports
from nbss import *
from smbconstants import *
from smb_config_store import *  
from testparser import *
from smb_logger import *
from ntlm import *
from smb_nt_err_codes import *
from smb_dos_err import *

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

try:
    import crypt
except ImportError:
    crypt = None

def date_time_from_epoch(largenumber):
    number = largenumber_to_int(largenumber)
    epoch = smbtime_to_utc(number)
    timetuple = time.localtime(epoch)
    print time.asctime(timetuple)

def is_linux_platform():
    osversion = platform.platform()
    osversion = osversion.lower()
    ret = string.find(osversion,'linux')
    if ( ret > -1):
        return 1
    return 0

DAYS_FROM_1601_TO_1970 = ((3*((100*365)+24))+((69*365)+17))
SECS_IN_A_DAY	       = (24*60*60)

def utc_to_smbtime(utc):
    msTime = DAYS_FROM_1601_TO_1970;  #Days from 1601 to 1970
    msTime *= SECS_IN_A_DAY; 	      #Seconds from 1601 to 1970
    msTime += UTC;		      #add in seconds since 1970
    msTime *= 10000000;	      #Convert seconds to 100ns intervals
    return msTime

def smbtime_to_utc(t):
    """Converts the given SMB time to seconds since the UNIX epoch.
    """
    x = t >> 32
    y = t & 0xffffffffL
    geoCalOffset = 11644473600.0
    # = 369.0 * 365.25 * 24 * 60 * 60 - (3.0 * 24 * 60
    # * 60 + 6.0 * 60 * 60)
    return ((x * 4.0 * (1 << 30) + (y & 0xfff00000L))
            * 1.0e-7 - geoCalOffset)

def get_nt_error_code(args):
    if ( len(args) == 0 ):
        return 0,0
    for tempstr in args:
        tempstr = tempstr.lower()
        ret = string.find(tempstr, 'error')
        if (ret != -1):
            tempstr = tempstr[(ret+string.find(tempstr[ret:],'=')+1):]
            tempstr = tempstr.strip()
            error = eval(tempstr)
            return 0,error
    return 0,0

def get_error_class_error_code(args):
    errclass = 0
    errcode = 0
    ret = 0
    if ( len(args) == 0 ):
        return errclass, errcode

    for tempstr in args:
        tempstr = tempstr.lower()
        if ( (string.find(tempstr, 'error')) != -1):
            tempstr = tempstr[(ret+string.find(tempstr[ret:],'=')+1):]
            tempstr = tempstr.strip()
            errcode = eval(tempstr)
        elif ( (string.find(tempstr, 'errclass')) != -1):
            tempstr = tempstr[(ret+string.find(tempstr[ret:],'=')+1):]
            tempstr = tempstr.strip()
            errclass = eval(tempstr)

    return errclass, errcode

def get_expected_error_value(client_cap, args):
    if ( client_cap & FLAGS2_NT_32_STATUS_CODE ):
        (errclass, errcode) = get_nt_error_code(args)
        return errclass, errcode
    else:
        (errclass, errcode) = get_error_class_error_code(args)
        return errclass, errcode

def largenumber_to_int(largenumber):
    """convert large integet to integer
    """
    (num_lsb, num_msb) = struct.unpack('<LL', largenumber)
    number = (num_msb << 32) | num_lsb
    return number

#SMB client states
CONNECTED_TO_SERVER = 0x00
RECV_BUFFER=65535
NEGOTIATED_STATE = 0x01
SESSION_ESTABLISHED   = 0x02
CONNECTED_TO_SHARE = 0x03
OPERATE_FILE = 0x04
DISCONNECT_SHARE = 0x05  # The completed state of the smbclient should be \
                         # now session_established.  The client has to \
                         # again connect to a share to do file operations
SESSION_DISCONNECT = 0x06# The completed state of the smbclient should be \
                         # now negotiate.  The client has to \
                         # again connect to a share to do file operations
RECV_BUFFER  = 65535

class SMB:
    def __init__(self, testfilename, localName=None):
        self.commands = {
            SMB_NEGOTIATE:          (self.cmd_negotiate_request,
                                     self.cmd_negotiate_response_wc17),
            SMB_TREE_DISCONNECT:    (self.cmd_tree_disconnect_request,
                                     self.cmd_tree_disconnect),
            SMB_SESSION_SETUP_ANDX: (self.cmd_session_setup_andx_request,
                                     self.cmd_session_setup_andx_wc3),
            SMB_LOGOFF:             (self.cmd_logoff_request,
                                     self.cmd_logoff),
            SMB_TREE_CONNECT_ANDX:  (self.cmd_tree_connect_andx_request,
                                     self.cmd_tree_connect_andx),
            SMB_ECHO:               (self.cmd_echo_request,
                                     self.cmd_echo),
            SMB_NT_CREATE_ANDX:     (self.cmd_nt_create_andx_request,
                                     self.cmd_nt_create_andx),
            SMB_OPEN_ANDX:     	    (self.cmd_nt_open_andx_request,
                                     self.cmd_nt_open_andx),
            SMB_GEN_CLOSE:          (self.cmd_close_request,
                                     self.cmd_close),
            SMB_READ_ANDX:          (self.cmd_read_andx_request,
                                     self.cmd_read_andx),
            SMB_WRITE_ANDX:         (self.cmd_write_andx_request,
                                     self.cmd_write_andx),
            SMB_SEEK_FILE:          (self.cmd_file_seek_request,
                                     self.cmd_file_seek),
            SMB_GEN_CHECK_DIR:      (self.cmd_check_dir_request,
                                     self.cmd_check_dir),
            SMB_GEN_OPEN:           (self.cmd_open_file_request,
                                     self.cmd_open_file),
            SMB_GEN_READ:           (self.cmd_read_file_request,
                                     self.cmd_read_file),
            SMB_GEN_WRITE:          (self.cmd_write_file_request,
                                     self.cmd_write_file),
            SMB_GEN_CREATE_DIR:     (self.cmd_create_dir_request,
                                     self.cmd_create_dir),
            SMB_GEN_DELETE_DIR:     (self.cmd_delete_dir_request,
                                     self.cmd_delete_dir),
            SMB_GEN_DELETE:         (self.cmd_delete_file_request,
                                     self.cmd_delete_file),
            SMB_WRITE_AND_CLOSE:    (self.cmd_write_and_close_file_request,
                                     self.cmd_write_and_close_file),
            SMB_GEN_RENAME:         (self.cmd_rename_request,
                                     self.cmd_rename),
            SMB_GEN_FLUSH:          (self.cmd_flush_request,
                                     self.cmd_flush),
            SMB_GEN_CHANGE_DIR:     (self.cmd_change_dir_request,
                                     self.cmd_none),
            SMB_LOCK_AND_READ:      (self.cmd_lockunlockbyterange_request,
                                     self.cmd_lockandread),
            SMB_WRITE_AND_UNLOCK:   (self.cmd_lockunlockbyterange_request,
                                     self.cmd_writeandunlock),
            SMB_LOCK_BYTE_RANGE:    (self.cmd_lockunlockbyterange_request,
                                     self.cmd_generic_response),
            SMB_UNLOCK_BYTE_RANGE:  (self.cmd_lockunlockbyterange_request,
                                     self.cmd_generic_response),
            SMB_GEN_LOCKING_ANDX:   (self.cmd_locking_andx_request,
                                     self.cmd_lock_unlock_andx),
            SMB_LOCKING_ANDX:       (self.cmd_not_implemented,
                                     self.cmd_locking_andx),
            SMB_TRANSACTION2:       (self.cmd_none,
                                     self.cmd_trans2),
            SMB_GEN_OPLOCK_BREAK:   (self.cmd_break_for_exlusive_oplock,
                                     self.cmd_none),
            SMB_GEN_WAIT:           (self.cmd_wait,      self.cmd_none),
            SMB_GEN_USE_SHARE:      (self.cmd_use_share, self.cmd_none),
            #QUERY_FS_INFO
            TRANS2_QUERY_FS_INFORMATION:    (self.cmd_trans2_queryfs_info_request,
                                             self.cmd_trans2),
            #QUERY_PATH_INFO
            TRANS2_QUERY_PATH_INFORMATION:  (self.cmd_trans2_querypath_request,
                                             self.cmd_trans2),
            #TRANS2_FIND_FIRST2
            TRANS2_FIND_FIRST2:    	        (self.cmd_trans2_findfirst2_request,
                                             self.cmd_trans2),
            TRANS2_FIND_NEXT2:     	        (self.cmd_not_implemented,
                                             self.cmd_trans2),
            TRANS2_QUERY_FILE_INFORMATION:  (self.cmd_trans2_queryfile_request,
                                             self.cmd_trans2),
            TRANS2_SET_FILE_INFORMATION:    (self.cmd_trans2_setfile_info_request,
                                             self.cmd_trans2),
            TRANS2_CREATE_DIRECTORY:	    (self.cmd_trans2_create_dir_request,
                                             self.cmd_trans2),
          #  TRANS2_SET_PATH_INFORMATION:   (self.cmd_trans2_setpath_info_request,
          #                                 self.cmd_trans2),
            SMB_FIND_CLOSE2:                (self.cmd_find_close2_request,
                                             self.cmd_find_close2),
            SMB_MOVE:                       (self.cmd_move_file_request,
                                             self.cmd_move_file),
##            SMB_COPY:                     (self.cmd_copy_file_request,
##                                                self.cmd_copy_file),
##            SMB_TRANSACTION:            (self.cmd_transaction_request,        self.cmd_transaction),
        }
        self.create_dir = {
                1000:	    self.cmd_trans2_create_dir,
        }
        self.query_fs_info = {
            SMB_INFO_ALLOCATION:        self.cmd_trans2_get_fsalloc_info,
            SMB_INFO_VOLUME:            self.cmd_trans2_get_vol_info,
            SMB_QUERY_FS_VOLUME_INFO:   self.cmd_trans2_get_fsvol_info,
            SMB_QUERY_FS_SIZE_INFO:     self.cmd_trans2_get_fssize_info,
            SMB_QUERY_FS_DEVICE_INFO:   self.cmd_trans2_get_fsdev_info,
            SMB_QUERY_FS_ATTRIBUTE_INFO:self.cmd_trans2_get_fsattr_info,
            SMB_QUERY_FS_FULL_SIZE_INFO:self.cmd_trans2_get_fs_fullsize_info,
        }
        self.query_path_info = {
            SMB_INFO_STANDARD:		 self.cmd_trans2_get_path_std_info,
            SMB_INFO_QUERY_EA_SIZE:      self.cmd_trans2_get_path_std_info,
##            SMB_INFO_QUERY_EAS_FROM_LIST: self.cmd_not_implemented,
##            SMB_INFO_QUERY_ALL_EAS:       self.cmd_not_implemented,
            #SMB_INFO_IS_NAME_VALID:
#                        self.cmd_trans2_get_dev_info,
            SMB_QUERY_FILE_BASIC_INFO:
                        self.cmd_trans2_get_path_file_basic_info,
            SMB_QUERY_FILE_STANDARD_INFO:
                        self.cmd_trans2_get_path_file_std_info,
            SMB_QUERY_FILE_EA_INFO:
                        self.cmd_trans2_get_path_file_ea_info,
            SMB_QUERY_FILE_NAME_INFO:
                        self.cmd_trans2_get_path_file_name_info,
            SMB_QUERY_FILE_ALLOC_INFO:
                        self.cmd_trans2_get_path_file_alloc_info,
            #SMB_QUERY_FILE_EOF_INFO:
                       # self.cmd_trans2_get_path_file_eof_info,
            SMB_QUERY_FILE_ALL_INFO:
                        self.cmd_trans2_get_path_file_all_info,
            SMB_QUERY_FILE_ALT_NAME_INFO:
                        self.cmd_trans2_get_path_file_altname_info,
            SMB_QUERY_FILE_STREAM_INFO:
                        self.cmd_trans2_get_path_file_stream_info,
            SMB_QUERY_FILE_COMPRESSION_INFO:
                        self.cmd_trans2_get_path_file_compress_info,
            SMB_QUERY_FILE_INTERNAL_INFO:
                        self.cmd_trans2_get_path_file_internal_info,
            SMB_FILE_NETWORK_OPEN_INFORMATION:
                        self.cmd_trans2_get_path_file_nw_open_info,
        }
        self.findfirst2 = {
            SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                        self.cmd_trans2_findfirst2_find_filedir_both_info,
            SMB_FIND_FILE_DIRECTORY_INFO:
                        self.cmd_trans2_findfirst2_file_dir_info,
            SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                        self.cmd_trans2_findfirst2_file_full_dir_info,
            SMB_FIND_FILE_NAMES_INFO:
                        self.cmd_trans2_findfirst2_filenames_info,
            SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
                        self.cmd_trans2_findfirst2_find_fileiddir_info,
            SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
                        self.cmd_trans2_findfirst2_find_fileiddir_both_info,
            SMB_INFO_STANDARD: 		    self.cmd_not_implemented,
            SMB_INFO_QUERY_EA_SIZE:         self.cmd_not_implemented,
            SMB_INFO_QUERY_EAS_FROM_LIST:   self.cmd_not_implemented,
        }
        self.findnext2 = {
            SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                        self.cmd_trans2_findnext2_find_filedir_both_info,
            SMB_FIND_FILE_DIRECTORY_INFO:
                        self.cmd_trans2_findnext2_find_file_dir_info,
            SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                        self.cmd_trans2_findnext2_find_file_full_dir_info,
            SMB_FIND_FILE_NAMES_INFO:
                        self.cmd_trans2_findnext2_find_filenames_info,
            SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
                        self.cmd_trans2_findnext2_find_fileiddir_info,
            SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
                        self.cmd_trans2_findnext2_find_fileiddir_both_info,
            SMB_INFO_STANDARD: 		    self.cmd_not_implemented,
            SMB_INFO_QUERY_EA_SIZE:         self.cmd_not_implemented,
            SMB_INFO_QUERY_EAS_FROM_LIST:   self.cmd_not_implemented,
        }
        self.set_file_info = {
            SMB_INFO_STANDARD:		    self.cmd_not_implemented,
            SMB_INFO_QUERY_EA_SIZE: 	    self.cmd_not_implemented,
            SMB_SET_FILE_BASIC_INFO: 	    self.cmd_generic_response,
            SMB_SET_FILE_DISPOSITION_INFO:  self.cmd_generic_response,
            SMB_SET_FILE_ALLOCATION_INFO:   self.cmd_generic_response,
            SMB_SET_FILE_END_OF_FILE_INFO:  self.cmd_generic_response,
         }
        self.trans_sub_cmd_loi_list = {
            TRANS2_QUERY_FS_INFORMATION:    self.query_fs_info,
            TRANS2_QUERY_PATH_INFORMATION:  self.query_path_info,
            TRANS2_QUERY_FILE_INFORMATION:  self.query_path_info,
            TRANS2_FIND_FIRST2:             self.findfirst2,
            TRANS2_FIND_NEXT2:              self.findnext2,
            TRANS2_SET_FILE_INFORMATION:    self.set_file_info,
            TRANS2_CREATE_DIRECTORY:	    self.create_dir,
        }
        self.request_list = {}
        self.morefiles = 0
        self.localName = localName
        self.ff2_sid_list = []
        self.transactions = {}
        self.transactions2 = {}
        self.userID = 0
        self.dup_userID = 0
        self.mid = 0
        self.tid = 0
        self.pid = os.getpid()
        # Stores the flag1 and flag2 value of the client
        self.cli_flags1 = 0
        self.cli_flags2 = 0
        # Stores the flag1 and flag2 value from the server
        self.server_flags1 = 0x00
        self.server_flags2 = 0x00
        self.smbrequest = ''
        self.smbresponse = ''
        self.capabilities_flags = 0x00
        self.sessionKey = 0x00000000
        self.dialect_negotiated = -1
        self.server_sec_blob_count = 0
        self.server_sec_blob = ''
        self.encKeyLen = 0
        self.encKey = ''
        self.maxRawSize = 0
        self.max_vc = 0
        self.max_mpx = 0
        self.max_transmit_size = 0
        self.domain_name = ''
        self.shareMode = 0
        self.security_mode = 0
        self.client_state  = CONNECTED_TO_SERVER
        self.lastfilename = ''
        self.rec_queue = ''
        self.totaldatalen = 0
        self.morepacket = 0
        self.lockandxtimeout = 0
        self.write_on_oplock_break = 0
        self.errorclass = 0
        self.errorcode = 0
        self.fdno = 0

        #Read the configuration of the server and the share name from the config file
        self.config = ConfigParser.ConfigParser()
        self.config.read('smbsetup.cfg')
        self.remoteName = self.config.get('setup', 'cifsserverip')
        self.smbport = eval(self.config.get('setup', 'port'))
        self.shareinfo = self.config.get('setup', 'sharename')
        self.shareinfo = string.split(self.shareinfo)
        self.username =  self.config.get('setup', 'username')
        self.password = self.config.get('setup', 'password')
        self.domain = self.config.get('setup', 'domain')
        self.dialect = self.config.get('setup', 'dialects')
        self.dialect = string.split(string.strip(self.dialect))
        self.smbresp_buf_size = eval(self.config.get(
                                'setup', 'smbresponsebufsize'))
        if ( self.smbresp_buf_size > 65535 ):
            self.smbresp_buf_size = 65535

        self.smbtransbufsize = eval(self.config.get
                                           ('setup', 'smbtransbufsize'))
        if ( self.smbtransbufsize > 65535 ):
            self.smbtransbufsize = 65535

        self.logfilename  = self.config.get('setup', 'logfile')
        self.lockandxtimeout = eval(self.config.get
                                           ('setup', 'lockandx_time_out'))

        #Read the flags1 support of pysmbclient
        if cmp(self.config.get('setup', 'pathcaseless'), 'on')  == 0:
            self.cli_flags1 |= FLAGS1_PATHCASELESS
        if cmp(self.config.get('setup','pathcanonicalize'), 'on') == 0:
            self.cli_flags1 |= FLAGS1_CANONICALIZE

        #Read the flags2 support of pysmbclient
        if cmp(self.config.get('setup','longname_in_response'), 'on') == 0:
            self.cli_flags2 |= FLAGS2_LONG_FILENAME_IN_RESPONSE

        if cmp(self.config.get('setup','longname_in_request'), 'on') == 0:
            self.cli_flags2 |= FLAGS2_LONG_NAME_IN_REQUEST

        if cmp(self.config.get('setup','smb_signature'), 'on') == 0:
            self.cli_flags2 |= FLAGS2_SECURITY_SIGNATURE

        if cmp(self.config.get('setup','security_negotiaton'), 'on') == 0:
            self.cli_flags2 |= FLAGS2_SECURITY_NEGOTIATION

        if cmp(self.config.get('setup','cap_dfs_resolve'), 'on') == 0:
            self.cli_flags2 |= FLAGS2_DFS_ENABLED
            self.capabilities_flags |= CAP_DFS_RESOLVE

        #Read the capabilities support of pysmbclient
        if cmp(self.config.get('setup','cap_unicode'), 'on') == 0:
            self.capabilities_flags |= CAP_UNICODE
            self.cli_flags2 |= FLAGS2_UNICODE

        if cmp(self.config.get('setup','cap_nt_smb_request'), 'on') == 0:
            self.capabilities_flags |= CAP_NT_SMB

        if cmp(self.config.get('setup','cap_nt_status_32'), 'on') == 0:
            self.capabilities_flags |= CAP_NT_STATUS_32
            self.cli_flags2 |= FLAGS2_NT_32_STATUS_CODE

        if cmp(self.config.get('setup','cap_large_files'), 'on') == 0:
            self.capabilities_flags |= CAP_LARGE_FILES
            self.capabilities_flags |= (CAP_READX | CAP_WRITEX)

        if cmp(self.config.get('setup','cap_unix_extension'), 'on') == 0:
            self.capabilities_flags |= CAP_UNIX_EXTENSION
            self.cli_flags2 |= FLAGS2_LONG_NAME_IN_REQUEST

        if cmp(self.config.get('setup','cap_extended_security'), 'on') == 0:
            self.capabilities_flags |= CAP_EXTENDED_SECURITY
            self.cli_flags2 |= FLAGS2_EXTENDED_ATTRIBUTES

        if cmp(self.config.get('setup','write_on_oplock_break'), 'on') == 0:
            self.write_on_oplock_break = 1

        if cmp(self.config.get('setup','cap_oplock_level2'), 'on') == 0:
            self.capabilities_flags |= CAP_LEVEL_II_OPLOCKS

        if cmp(self.config.get('setup','cap_nt_find'), 'on') == 0:
            self.capabilities_flags |= CAP_NT_FIND

        if cmp(self.config.get('setup','cap_info_passthru'), 'on') == 0:
            self.capabilities_flags |= CAP_INFO_PASSTHRU

        if cmp(self.config.get('setup','cap_lock_and_read'), 'on') == 0:
            self.capabilities_flags |= CAP_LOCK_AND_READ
            self.cli_flags1 |= FLAGS1_LOCK_AND_READ
        # Capabilities of the pysmbclient
        self.dfs_supported = 0
        self.fileoperation = 0
        self.echocount = 0

        # Populated as and when the cifsclient communicates with the server
        self.fid_db = FIDStore()
        # Contains information regarding the shares and their TID
        self.share_config_store = SMBShare()
        self.testparser = TestCodeParser(testfilename)
        self.logger = MessageLogger(open(self.logfilename, "a"))
        self.uniencoder = codecs.getencoder('utf-16-le')

    def getfidno(self):
        """appends integer fdno with string fd
        """
        fdnostring = "%s%d"%('$fd',self.fdno)
        self.fdno = self.fdno + 1
        return fdnostring

    def __del__(self):
        self.logger.close()
        self.client_socket.close()

    def connectToServer(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ( self.client_socket < 0 ):
            return 0
        self.client_socket.connect((self.remoteName, self.smbport))
        return 1

    def dataReceived(self):
        filelen = 0
        while 1:
            try:
                recv_data = self.client_socket.recv(RECV_BUFFER)
            except:
                thread.interrupt_main()
                break
            if not recv_data:
                continue
            # Verify the NBT struct before parsing the SMB packet.
            self.smbresponse = recv_data
            status, moresegment, length, smbdata = NBT.verifyNBT(recv_data)
            if (status and moresegment == 0):
                self.testparser.readstop = 0
                thread.start_new_thread(self.parse_smb_response, (smbdata,))
            if (moresegment):
                #print 'More segments received'
                #print 'Data len = %d'%len(recv_data)
                self.testparser.received = 1;
                pass
            else:
                self.fileoperation = 0
                pass
    # This function parses test script file and generates the SMB request
    # packets for every valid keyword found.
    # Argument for this function is:
    #   filename: filename of the test file.
    #
    def parse_test_script(self):
        if self.testparser.open_test_file():
            while 1:
                while (self.testparser.readstop):
                    time.sleep(1)
                ln = self.testparser.testfile_fd.readline()
                if not ln:
                    #print 'End of test script'
                    time.sleep(2)
                    thread.interrupt_main()
                    self.testparser.close_test_file()
                    break
                status, cmd, arglist = self.testparser.get_next_command_and_args(ln)
                if status == 1 and cmd != SMB_NONE:
                    req_res_list = self.commands[cmd]
                    req_cmd = req_res_list[0]
                    print req_cmd.__name__
                    req_cmd(cmd, arglist)
            else:
                print "file is empty!!"
                failed = 0
            self.testparser.close_test_file()

    def get_trans2_response_parser(self, subcmd, lev_of_interest):
        smbcmdset = self.trans_sub_cmd_loi_list[subcmd]
        return smbcmdset[lev_of_interest]

    def cmd_wait(self, cmd, args):
        if ( len(args) == 0):
            time.sleep(10)
        else:
            time.sleep(eval(args[0]))

    def cmd_use_share(self, cmd, args):
        if ( len(args) < 1):
            print 'Missing sharename as parameter'
            return
        else:
            tid = self.share_config_store.get_tid_from_share(args[0])
            if ( tid != -1 ):
                print 'Tree ID for the share name could not be found'
                return
        self.tid = tid


    def cmd_break_for_exlusive_oplock(self, cmd, args):
        self.testparser.readstop = 1

    def cmd_none(self):
        print 'No command'

    def send_smb_packet(self, cmd, param='', data='', error = 0,
                        subcmd=0,level_of_interest=0,sid=0,
                        status=0, flags1=0, flags2=0,tid=0, mid=0):
        while ( self.morepacket ):
            time.sleep(1)
        wordCount = len(param)
        self.smbrequest = ''
        smbflags2 = self.cli_flags2

        if (self.userID != self.dup_userID):
            self.userID = self.dup_userID

        self.smbrequest = struct.pack('<4sBLBH12sHHHHB', '\xffSMB', cmd,
                          status, self.cli_flags1, smbflags2,
                          '\0' * 12, self.tid, os.getpid(), self.userID,
                          self.mid,wordCount / 2)
        self.smbrequest += param + struct.pack('<H', len(data)) + data

        nbtrequest = NBT.construct_nbt_request(self.smbrequest)
        self.smbrequest = nbtrequest + self.smbrequest
        smbdatalist = [ cmd, self.smbrequest, self.lastfilename,
                        self.errorclass, self.errorcode ]
##      Store the smbrequest till we recieve the response for the request sent
        if add_to_request_list(self.request_list,self.mid, smbdatalist):
            self.logger.log('Info: Request to server with  MID = %d' %mid)
###     Store the trans2 request to a set to once the response frm the server is
##      recevied call the appropriate decode method.
        if ( cmd == SMB_TRANSACTION2 ):
            trans2req = { self.mid : [ self.tid, self.userID, subcmd,
                                       level_of_interest, sid,  '', '']}
            if (add_to_request_list(self.transactions2,self.mid , trans2req)):
                self.logger.log('Info: Trans2 Request is added to the transaction list')

        self.client_socket.send(self.smbrequest)
        self.mid+=1

    def decodeSMBResponse(self, data):
        # The reserved/extra indicate the fields that can be ignored/of least
        # importance while parsing the SMB response
        if (self.capabilities_flags & CAP_NT_STATUS_32):
            (smb_proto_sig, cmd,err_code, flags1, flags2,
             extra, tid, pid, uid, mid,
             wcount) = struct.unpack('<4sBLBH12sHHHHB', data[:33])
            err_class = 0
        else:
            (smb_proto_sig, cmd,err_class,reserved,err_code,flags1,flags2,
             extra, tid, pid, uid, mid,
             wcount) = struct.unpack('<4sBBBHBH12sHHHHB', data[:33])

        param_end = 33 + wcount * 2
        if self.request_list.has_key(mid) :
            self.logger.log('Info: Response for MID = %d' %mid)
            self.request_list.pop(mid)

        elif ( cmd != SMB_ECHO or cmd != SMB_READ_ANDX or cmd != SMB_READ or
             cmd != SMB_TRANSACTION2 ):
                self.logger.log('Warning: Response from server has \
                                incorrect MID = %d' %mid)
        return (smb_proto_sig, cmd, err_class, err_code, flags1,
                flags2, tid, uid, mid, wcount,
                data[33:param_end], data[param_end:])


    def server_smb_packet(self, smb_proto_sig, cmd_num, errClass,
                          errCode, flags1, flags2, tid, uid,
                          mid, word_count, params, data):
        smbrequest = self.request_list.get(mid)
        if ( smbrequest!= None and len(smbrequest) > 2):
            self.lastfilename = smbrequest[2]
        errfound = 0
        if smb_proto_sig == '\xffSMB':
            if (self.capabilities_flags & CAP_NT_STATUS_32):
                if ( errCode != 0):
                    if ( self.errorcode == 0xFFFFFFFF ):
                        errfound = 1

                    if ( errCode == self.errorcode):
                        self.logger.log('command %d completed successfully with\
                            expected error code' %cmd_num)
                        errfound = 1

            if(self.capabilities_flags & CAP_NT_STATUS_32 == 0 and
                  (errClass != 0 or errCode != 0)):
                if self.errorclass == errClass or self.errorcode == errClass:
                    self.logger.log('command %d completed successfully with\
                            expected error code' %cmd_num)
                    errfound = 1

                if (self.errorcode == 0xFFFFFFFF ):
                    errfound = 1

            if errClass == 0x00 and errCode == 0x00:
                if cmd_num == SMB_RENAME:
                    self.cmd_rename(flags1,flags2,tid,uid,mid,params,data,
                                    errClass, errCode)
                    #print self.cmd_rename.__name__
                    return
                if cmd_num == SMB_DELETE_DIR:
                    self.cmd_delete_dir(flags1,flags2,tid,uid,mid,params,
                                        data,errClass, errCode)
                    #print self.cmd_delete_dir.__name__
                    return
                if cmd_num == SMB_DELETE:
                    self.cmd_delete_file(flags1, flags2, tid, uid, mid, params,
                                        data,errClass, errCode)
                    #print self.cmd_delete_file.__name__
                    return
                if cmd_num == SMB_CREATE_DIR:
                    self.cmd_create_dir(flags1, flags2, tid, uid, mid, params,
                                         data,errClass, errCode)
                    #print self.cmd_create_dir.__name__
                    return
                if cmd_num == SMB_OPEN:
                    self.cmd_open_file(flags1, flags2, tid, uid, mid, params,
                                        data,errClass, errCode)
                    #print self.cmd_open_file.__name__
                    return
                if cmd_num == SMB_READ:
                    self.cmd_read_file(flags1, flags2, tid, uid, mid, params,
                                        data,errClass, errCode)
                    #print self.cmd_read_file.__name__
                    return
                if cmd_num == SMB_WRITE:
                    self.cmd_write_file(flags1, flags2, tid, uid, mid, params,
                                        data,errClass, errCode)
                    #print self.cmd_write_file.__name__
                    return
                if cmd_num == SMB_CLOSE:
                    self.cmd_close(flags1,flags2,tid,uid,mid,params,data,errClass, errCode)
                    #print self.cmd_close.__name__
                    return
            #if cmd_num == SMB_CHANGE_DIR:
            #    self.cmd_change_dir(flags1, flags2, tid, uid, mid, params,
            #                        data)
            #    return
                if cmd_num == SMB_FLUSH:
                    self.cmd_flush(flags1,flags2,tid,uid,mid,params,data,errClass, errCode)
                    #print self.cmd_flush.__name__
                    return
                if cmd_num == SMB_CHECK_DIR:
                    self.cmd_check_dir(flags1, flags2, tid, uid, mid, params,
                                        data,errClass, errCode)
                    #print self.cmd_check_dir.__name__
                    return
            if (errfound == 0 and (errClass == 0 and errCode == 0)):
                    req_res_list = self.commands[cmd_num]
                    cmd = req_res_list[1]

                    if word_count == 0 and cmd_num == SMB_LOCKING_ANDX:
                        self.cmd_generic_response(flags1, flags2, tid, uid, mid,
                                              params,data,errClass, errCode)
                    if word_count == 0 and cmd_num == SMB_NT_CREATE_ANDX:
                        self.cmd_generic_response(flags1, flags2, tid, uid, mid,
                                              params,data,errClass, errCode)
                    elif word_count == 1 and cmd_num == SMB_NEGOTIATE:
                        self.cmd_negotiate_response_wc1(flags1, flags2, tid,uid, mid,
                                                 params, data, errClass, errCode)
                    elif word_count == 13 and cmd_num == SMB_NEGOTIATE:
                        self.cmd_negotiate_response_wc13(flags1, flags2, tid,uid, mid,
                                                 params, data, errClass, errCode)
                    elif word_count == 17 and cmd_num == SMB_NEGOTIATE:
                        self.cmd_negotiate_response_wc17(flags1, flags2, tid,uid, mid,
                                                 params, data, errClass, errCode)
                    elif word_count == 3 and cmd_num == SMB_SESSION_SETUP_ANDX:
                        self.cmd_session_setup_andx_wc3(flags1, flags2, tid,uid, mid,
                                                  params, data,errClass, errCode)
                    elif word_count == 4 and cmd_num == SMB_SESSION_SETUP_ANDX:
                        self.cmd_session_setup_andx_wc4(flags1, flags2, tid,uid, mid,
                                                  params, data,errClass, errCode)
                    else:
                        #print cmd.__name__
                        cmd(flags1, flags2, tid, uid, mid, params,
                            data,errClass, errCode)

                        if ( self.request_list.has_key(mid) and len(self.request_list)):
                            self.request_list.pop(mid)
            else:
                self.fileoperation = 0
                #print ("Errorclass = %d, error code = %d"%(errClass, errCode))
                if ( self.request_list.has_key(mid) and len(self.request_list)):
                    self.request_list.pop(mid)

        thread.exit_thread()

    def parse_smb_response(self, smbdata):
        ret = self.server_smb_packet(*(self.decodeSMBResponse(smbdata)))
        self.lastfilename = ''

    def cmd_negotiate_request(self, cmd, authlist):
        if ( self.client_state != CONNECTED_TO_SERVER ):
            self.logger.log('Client is in incorrect state')
            return
        (self.errorclass,
        self.errorcode)= get_expected_error_value(self.capabilities_flags,
                                                  authlist)
        data = ''
        dialectlist = []
        if ( len(authlist) == 0):
            dialectlist = self.dialect

        elif ( len(authlist) > 0 ):
            dialectlist = authlist
            self.dialect = authlist

        for auth in dialectlist:
            indx  = auth_mode_exist(auth)
            if ( indx  != -1):
                alist = SMB_AUTH_MODE_LIST[indx]
                data+= alist[1]
        self.send_smb_packet(cmd, '', data=data )
        self.fileoperation = 1

    ## Negotiate response with word count 1.  This function will be called
    ## mostly when PC Network Program 1.0 is chosen by server
    def cmd_negotiate_response_wc1(self, flags1, flags2, tid, uid, mid,
                                   params, data,errClass, errCode):
        (selDialect,) = struct.unpack('<H', params[:2])
        if selDialect == 65535:
            self.logger.log("Unsupported Authentication method chosen \
                            from the CIFS server.")
            print("Unsupported Authentication method in CIFS Server")
            return
        self.dialect_negotiated = selDialect
        self.logger.log('Server selected %s dialect'%self.dialect[selDialect])
        self.server_flags1 = flags1
        self.server_flags2 = flags2
        self.client_state = NEGOTIATED_STATE
        self.fileoperation = 0

    ## Negotiate response with word count 1.  This function will be called
    ## mostly when LANMAN 1.0 is chosen by server
    def cmd_negotiate_response_wc13(self, flags1, flags2, tid, uid, mid,
                               params, data,errClass, errCode):
        (selDialect,) = struct.unpack('<H', params[:2])
        if selDialect == 65535:
            self.logger.log("Unsupported Authentication mode from the server.")
        self.logger.log('Server selected %s dialect' %self.dialect[selDialect])
        self.dialect_negotiated = selDialect

        # NT LM 0.12 dialect selected
        (security_mode, self._maxTransmitSize, self.maxmpx, self.maxvc,
         rawMode, self.sessionKey, datetime, serverzone,
         keyLength,_) = struct.unpack('<HHHHHllHHH', params[2:])

        (bytecount,) = struct.unpack('<H', data[:2])
        self._canReadRaw = rawMode & 0x01
        self._canWriteRaw = rawMode & 0x02
        self._isPathCaseless = flags1 & FLAGS1_PATHCASELESS

        if keyLength > 0 and bytecount == keyLength and \
            len(data[2:]) >= keyLength:
            self._encKey = data[2:keyLength]
        else:
            self._encKey = ''

        self.flags1 = flags1
        self.flags2 = flags2

        self.client_state = NEGOTIATED_STATE
        self.fileoperation = 0


    ## Negotiate response with word count 1.  This function will be called
    ## mostly when NTLM 0.12 and greater is chosen by server
    def cmd_negotiate_response_wc17(self, flags1, flags2, tid, uid, mid,
                               params, data,errClass, errCode):
        (selDialect,) = struct.unpack('<H', params[:2])
        if selDialect == 65535:
            print "Remote server does not have none of the authentication \
                    mechanisms in common."
        self.logger.log('Server selected %s dialect'%self.dialect[selDialect])

        # NT LM 0.12 dialect selected
        (security_mode, self.maxmpx, self.maxvc, self.max_transmit_size,
         self.maxRawSize, self.sessionKey, capability, _,
         self.encKeyLen) = struct.unpack('<BHHllll10sB', params[2:])

        if capability & CAP_EXTENDED_SECURITY:
            self.logger.log("pysmbclient does not support extended \
                    security validation. ")

        self.security_mode = security_mode & SECURITY_AUTH_MASK
        self.shareMode = security_mode & SECURITY_SHARE_MASK

        (bytecount,) = struct.unpack('<H', data[:2])

        self.encKey = data[2: 2+self.encKeyLen]
        oemoffset = 2 + self.encKeyLen
        oemendoffset = (string.find(data[oemoffset:], '\x00\x00') + 1)
        self.domain_name = data[oemoffset:oemoffset+oemendoffset+2]
        self.servername = data[oemoffset+oemendoffset+2:]
        self.flags1 = flags1
        self.flags2 = flags2

        self.client_state = NEGOTIATED_STATE
        self.fileoperation = 0


    def cmd_session_setup_andx_request(self, cmd, data):
        while(self.client_state < NEGOTIATED_STATE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode)=get_expected_error_value(self.capabilities_flags,
                                                  data)
        if ((cmp(self.dialect[self.dialect_negotiated],
                 'SMB_DIALECT_NTLM12')==0 ) or
             (cmp(self.dialect[self.dialect_negotiated],
                  'SMB_DIALECT_NTLM12_1')==0 )):
            self.cmd_session_setup_andx_req_w13(self.username,
                                              self.password, self.domain)

        elif ( (cmp(self.dialect[self.dialect_negotiated] ,
                    'SMB_DIALECT_LM12') ==0) or
               (cmp(self.dialect[self.dialect_negotiated] ,
                    'SMB_DIALECT_LM21') ==0) or
               (cmp(self.dialect[self.dialect_negotiated] ,
                    'SMB_DIALECT_LANMAN10') ==0) or
               (cmp(self.dialect[self.dialect_negotiated] ,
                    'SMB_DIALECT_WWG') ==0) or
               (cmp(self.dialect[self.dialect_negotiated] ,
                    'SMB_DIALECT_PC_NWK') ==0) ):
            # should be changed to *_wc13 after implementing unicode support
            self.cmd_session_setup_andx_req_w10(self.username,
                                              self.password, self.domain)

##############################################
#Helper functions for session setup
##############################################
    def get_ntlmv1_response(self, key):
        challenge = self.encKey
        return get_ntlmv1_response(key, challenge)


    def login_plaintext_password(self, user, password, domain = ''):
        # Password is only encrypted if the server passed us an
        # "encryption key" during protocol dialect negotiation
        if password and self.encKey:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash((self.flags2 & FLAGS2_UNICODE) , password)
            lmhash = self.get_ntlmv1_response(lmhash)
            nthash = self.get_ntlmv1_response(nthash)
        else:
            lmhash = password
            nthash = ''
        return user, lmhash, nthash, domain


    def cmd_session_setup_andx_req_w10(self, username, password, domain=''):
        if self.encKey and crypt:
            password = crypt.hash(password, self.encKey)
        passworduni = unicode(password)
        passwordunilen = len(passworduni)
        usernameuni = unicode(username)
        params = struct.pack('<ccHHHHLHL','\xff','\0',0,65535,self.maxmpx,
                             self.maxvc,self.sessionKey,len(password),0)

        datas = "%s%s\0%s%s\0%s\0" % (password, username, domain,
                                        os.name, 'pysmbclient')
        self.send_smb_packet(SMB_SESSION_SETUP_ANDX, param=params, data=datas)
        self.fileoperation = 1

    # Used only during challenge response
    def cmd_session_setup_andx_req_w12(self, username, password, domain=''):
        passworduni = unicode(password)
        passwordunilen = len(passworduni)
        usernameuni = unicode(username)
        params = struct.pack('<ccHHHHLHHLL', '\xff', '\0', 0, 65535, 2,
                             os.getpid(), self.sessionKey, len(password), 0, 0,
                             self.capabilities_flags)
        datas = "%s%s\0%s\0%s\0%s\0" % (password, username, domain,
                                        os.name, 'pysmbclient')
        self.send_smb_packet(SMB_SESSION_SETUP_ANDX, param=params, data=datas)
        self.fileoperation = 1


##    Request to be send for ntlm v1
    def cmd_session_setup_andx_req_w13(self, username, password, domain=''):
        (user, asciipwd, unipwd,
        domain) = self.login_plaintext_password(username, password)
        domname = unicode(self.domain_name,'utf_16_le')
        domname = domname.encode('utf8')
        passwordunilen = len(unipwd)
        if ( self.flags2 & FLAGS2_UNICODE):
            params = struct.pack('<ccHHHHLHHLL', '\xff', '\0', 0,
                            65530, self.mid,os.getpid(), self.sessionKey,
                            0,passwordunilen,0,self.capabilities_flags)
            uniuser = self.uniencoder(user)
            unidomname = self.uniencoder(domname)
            uniosname = self.uniencoder(os.name)
            uniname = self.uniencoder('pysmbclient\0')
            if ( is_linux_platform() ):
                datas = "%s%s\0%s\0\0%s%s\0\0%s" % ('',unipwd,uniuser[0],
                                unidomname[0],uniosname[0],
                                #'',uniosname[0],
                                uniname[0] )
            else:
                datas = "%s%s\0%s\0\0%s%s\0\0%s" % ('',unipwd,uniuser[0],
                                unidomname[0],uniosname[0],
                                uniname[0] )

        else:
            params = struct.pack('<ccHHHHLHHLL', '\xff', '\0', 0, 65530,
                             self.mid,os.getpid(), self.sessionKey,
                             len(asciipwd),0,0,self.capabilities_flags)
            datas = "%s%s%s\0%s\0%s\0%s\0" % (asciipwd,'',user, domname[:-1],
                                        os.name, 'pysmbclient')

        self.send_smb_packet(SMB_SESSION_SETUP_ANDX, param=params, data=datas)
        self.fileoperation = 1


    def cmd_session_setup_andx_wc4(self, flags1, flags2, tid, uid, mid, params,
                                 data,errClass, errCode):
        self.userID = uid
        self.dup_userID = uid
        (andx_cmd, andx_resrvd, andx_offset, action,
                 sec_blob_len,) = struct.unpack('<BBHHH', params)
        (bytecount,) = struct.unpack('<H', data[:2])

        sec_blob = data[2: sec_blob_len]
        self.logger.log('Skipping over Server OS, LANMAN, DOMAIN name')
        self.client_state = SESSION_ESTABLISHED
        self.server_flags1 = flags1
        self.server_flags2 = flags2
        self.fileoperation = 0


    def cmd_session_setup_andx_wc3(self, flags1, flags2, tid, uid, mid,
                                 params, data,errClass, errCode):
        self.userID = uid
        self.dup_userID = uid
        (andx_cmd, andx_reserved, andx_offset,
         action,) = struct.unpack('<ccHH', params[:6])

        (bytecount,) = struct.unpack('<H', data[:2])
        self.server_flags1 = flags1
        self.server_flags2 = flags2
        self.client_state = SESSION_ESTABLISHED
        self.fileoperation = 0

    def cmd_tree_connect_andx_request(self, cmd, sharelist):
        while(self.client_state != SESSION_ESTABLISHED or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode)=get_expected_error_value(self.capabilities_flags,
                                                  sharelist)
        service = '?????'
        share = ''

        if ( len(sharelist) == 0 ):
            self.logger.log("Tree connect request has no argument, defaulting \
                            to share in the setup file")
            if ( len(self.shareinfo[0]) > 1):
                share = self.shareinfo[0]

        if (len(sharelist) > 1 and cmp(sharelist[0].upper(), 'IPC$') == 0):
                service = 'IPC$'

        if (len(sharelist) >= 1):
            share = sharelist[0]
        self.lastfilename = share
        self.tree_connect_req(join(self.remoteName, share), service)
        self.fileoperation = 1


    def tree_connect_req(self, path, service):
        #password = self.get_ntlmv1_response(compute_lmhash(self.password))
        unipath = self.uniencoder((path.upper()+'\0'))[0]
        if ( self.cli_flags2 & FLAGS2_UNICODE ):
            datas = '\0' + unipath + service + '\0'
        else:
            datas = '\0' + path.upper() + '\0' + service + '\0'
        self.send_smb_packet(SMB_TREE_CONNECT_ANDX,
                 struct.pack('<BBHHH', 0x0ff,0, 0, 0, 1), datas)

    def cmd_tree_connect_andx(self, flags1, flags2, tid, uid, mid, params,
                            data,errClass, errCode):
        self.tid = tid
        service = ''
        file_system = ''
        (bytecount,) = struct.unpack('<H', data[:2])
        (optional_support,) = struct.unpack('<H', params[len(params)-2:])

        for i, c in enumerate(data[2:]):
            if c == '\x00':
                break
            service += c
        file_system = data[i+2+1: len(data) -1]
        # Store the Tidno along with the share details in the config store
        tid_list = [tid, self.lastfilename, '',service, file_system,
                    optional_support, self.remoteName]

        if (self.share_config_store.list_add(tid_list)):
            self.client_state = CONNECTED_TO_SHARE
        else:
            print 'Adding share to list failed'
        self.fileoperation = 0

    def cmd_tree_disconnect_request(self, cmd, sharelist):
        share = ''
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    sharelist)
        if ( len(sharelist) == 0 ):
            self.logger.log('Tree connect request has no argument, defaulting \
                            to share in the setup file')
            if ( len(self.shareinfo[0]) > 1):
                share = self.shareinfo[0]
        if (len(sharelist) >= 1):
            share = sharelist[0]

        tidno = self.share_config_store.get_tid_from_share(share)
        if ( tidno == -1):
            print 'Invalid share name'

        self.tid = tidno
        self.tree_disconnect_req(tidno)

    def tree_disconnect_req(self, tidno):
        params = struct.pack('<B', 0)
        self.send_smb_packet(SMB_TREE_DISCONNECT, param=params, tid=tidno)
        self.fileoperation = 1


    def cmd_tree_disconnect(self, flags1, flags2, tid, uid, mid, params,
                           data,errClass, errCode):
        self.client_state = SESSION_ESTABLISHED
        self.fileoperation = 0


    def cmd_echo_request(self, cmd, echostring):
        while ( self.client_state < SESSION_ESTABLISHED ):
            time.sleep(1)
        datas = ''
        if ( len(echostring) < 2):
            print 'Usage echo [count] [echo string]'
            return

        count = echostring[0]
        count = eval(count)
        params=struct.pack('<H', count)
        clidata = echostring[1:]
        for strings in clidata:
            datas += strings
            datas += ' '

        datas = datas[0:-1]
        self.send_smb_packet(cmd, param=params, data=datas)
        self.fileoperation = 1
        self.echocount = count


    def cmd_echo(self, flags1, flags2, tid, uid, mid,params,
                 data,errClass, errCode):
        if (self.echocount):
            self.echocount -= 1
            return
        self.fileoperation = 0
        print data

    def cmd_logoff_request(self, cmd, data):
        while(self.client_state < SESSION_ESTABLISHED or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    data)
        params = struct.pack('<BBH', 0x0ff, 0, 0)
        self.send_smb_packet(SMB_LOGOFF, param=params)

    def cmd_logoff(self, flags1, flags2, tid, uid, mid, params,
                   data,errClass, errCode):
        pass


#OPNE_ANDX command
    def nt_open_andx_request(self, filename,  flags, desiredaccess,
                               searchattr, fileattr, crtime, openmode,
                               allocsize):
        datas = ''
        if (self.capabilities_flags & CAP_UNICODE):
            unifilename = self.uniencoder((filename+'\0'))[0]
            filenamelen = len(filename) * 2
            datas +='\0'
        else:
            unifilename = filename + '\0'
            filenamelen = len(filename)

        params = struct.pack('<ccHHHHHLHLLL', '\xff','0', 0,
                             flags,desiredaccess,searchattr,
                             fileattr, crtime, openmode,
                             allocsize, 0, 0)
        datas+=unifilename
        self.lastfilename = filename

        tid = self.share_config_store.get_tid_from_share(self.shareinfo[0])
        if ( tid < 0 ):
            print ('Invalid share')
        fidlist = [ filename, 0x0000, tid, flags, desiredaccess,
                    searchattr, fileattr, crtime, openmode,
                    0, 0, 0, 0, self.getfidno() ]
        if (self.fid_db.list_add(fidlist, 1)):
            self.logger.log('FID added to config store')
        else:
            print 'FID cannot be added to config store'

        self.send_smb_packet(SMB_OPEN_ANDX, param=params, data=datas)
        self.fileoperation = 1


    def cmd_nt_open_andx_request(self, cmd, open_params):
        desiredaccess =0
        allocsize = 0
        openmode = 0
        while ( self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if len(open_params) == 1:
            self.logger.log('nt_open_andx_request requires additional argument')

        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    open_params)
        if len(open_params) >= 2:
            if ( cmp(open_params[0],'new') == 0):
                openmode = 0x10
                desiredaccess = 0x0043
                allocsize = 0x00
            elif ( cmp(open_params[0],'exist') == 0):
                openmode = 0x01
                desiredaccess=0x0002
                allocsize = 0x10000000
            elif ( cmp(open_params[0],'trunc') == 0):
                openmode = 0x12
                desiredaccess=0x0002
                allocsize = 0x10000000

            filename = open_params[1]
            flags = 0 #eval(open_params[1])
            searchattr = 6#eval(open_params[3])
            fileattr = 0 #eval(open_params[3])
            crtime = 0 #time.time()

        self.nt_open_andx_request(filename,  flags, desiredaccess,
                               searchattr, fileattr, crtime, openmode,
                               allocsize)

    def cmd_nt_open_andx(self, flags1, flags2, tid, uid, mid,
                               params, data,errClass, errCode):
        if (len(params) > 30):
            param = params[:30]
        else:
            param = params
        (andx_cmd, _, andx_offset, fid, fileattr, lwrite, filesize,
         granted_access, file_type, ipc_state,action,
             serverfid,_,) = struct.unpack('<BBHHHLLHHHHLH', param)

        (bytecount,) = struct.unpack('<H', data[:2])
        self.fid_db.set_fid_on_filename(self.lastfilename, fid, 1)
        ret = (self.fid_db.set_fileinfo_on_filename(self.lastfilename,
                                         filesize, filesize, file_type, 0,1) )
        if (ret):
            self.logger.log('Fileinfo added to fid')
        else:
            print 'Fileinfo not added to fid, error, file operation will fail'
        self.fileoperation = 0
##Example of open command
##ntcreate file1  oplock=0x0 accessmask= fileattr=
##            sharemode= disposition= createoptions
##            impersonation= securityflags=
##
    def cmd_nt_create_andx_request(self, cmd, create_params):
        amfound = 0
        fattrfound =0
        smfound = 0
        cofound = 0
        dispfound = 0
        oplockfound =0
        impersonationfound = 0
        securtiyfound = 0
        while((self.client_state < CONNECTED_TO_SHARE) or self.fileoperation):
            time.sleep(1)
        if len(create_params) == 1:
            print 'nt_create_andx is missing file open arguments \n \
               defaulting to open existing file with read options'
            self.logger.log('nt_create_andx_request requires additional argument')
        (self.errorclass,
        self.errorcode)=get_expected_error_value(self.capabilities_flags,
                                                 create_params)
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

        self.nt_create_andx_request(filename, createflags, accessmask,
                                fileattr,sharemode,disposition,createoptions,
                                impersonation, security_flags)

    def nt_create_andx_request(self, filename, createflags, accessmask,
                               fileattr, sharemode, disposition,
                               create_opt, impersonation, security_flags):
        datas =''
        if (self.capabilities_flags & CAP_UNICODE ):
            unifilename = self.uniencoder((filename+'\0'))[0] #+ '\0'
            filenamelen = len(filename) * 2
            datas+='\0'
        else:
            unifilename = filename + '\0'
            filenamelen = len(filename)
        params = struct.pack('<ccHcHLLL8sLLLLLB', '\xff','0', 0,
                                 '\0', filenamelen,createflags, 0x00,
                                 accessmask,'\0' * 8,fileattr,sharemode,
                                 disposition,create_opt,impersonation,
                                 security_flags)
        datas += unifilename
        self.lastfilename = filename

##        ['filename', 'fid', 'tid','create_flags', 'access_mask',
##         'file_attr', 'share_access','create_options', 'security_flags',
##         'disposition','impersonation', ]
        tid = self.share_config_store.get_tid_from_share(self.shareinfo[0])
        if ( tid < 0 ):
            print ('Invalid share')
        fidlist = [ filename, 0x0000, tid, createflags, accessmask,
                    fileattr, sharemode, create_opt,security_flags,
                    disposition,impersonation, 0, 0, 0,self.getfidno() ]
        if (self.fid_db.list_add(fidlist)):
            self.logger.log('FID added to config store')
        else:
            print 'FID cannot be added to config store'
        self.send_smb_packet(SMB_NT_CREATE_ANDX, param=params, data=datas)
        self.fileoperation = 1


    def cmd_nt_create_andx(self, flags1, flags2, tid, uid, mid,
                               params, data,errClass, errCode):
        if (len(params) > 68):
            param = params[:68]
        else:
            param = params
        (andx_cmd, _, andx_offset,oplock_level,
         fid, create_action, created_ts, lastaccess_ts,
         lastwrite_ts, change_ts, fileattr, alloc_size, eof,
         file_type, ipc_state,
         isdir,) = struct.unpack('<BBHBHL8s8s8s8sL8s8sHHB', param)
        (bytecount,) = struct.unpack('<H', data[:2])

        totalallocsize = largenumber_to_int(alloc_size)
        eofsize = largenumber_to_int(eof)
        print 'File size = %ld'%eofsize
        print 'Alloc File size = %ld'%totalallocsize
        

#       (alloc_size_lsb, alloc_size_msb) = struct.unpack('<LL', alloc_size)
#        totalallocsize = (alloc_size_msb << 32) | alloc_size_lsb
#        (eof_lsb, eof_msb) = struct.unpack('<LL', eof)
#        eofsize = eof_msb << 32 | eof_lsb
        self.fid_db.set_fid_on_filename(self.lastfilename, fid)
        if (self.fid_db.set_fileinfo_on_filename(self.lastfilename,
                                        eofsize, totalallocsize, file_type,
                                        oplock_level) ):
            self.logger.log('Fileinfo added to fid')
        else:
            print 'Fileinfo not added to fid, error, file operation will fail'
        self.fileoperation = 0

##CLOSE Request
    def cmd_close_request(self, cmd, data):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    data)
        if ( len(data) <= 0 ):
            print 'Closefile command requires filename as argument'
        status, fid = self.fid_db.get_fid_from_filename(data[0])
        if ( fid == -1 and status == 0):
            print '%s is not in FID store' %(data[0])
            return
        params = struct.pack('<H',fid)
        params+='ffff'
        datas = ''
        self.lastfilename = data[0]
        self.fileoperation = 1
        self.testparser.readstop = 1
        self.send_smb_packet(SMB_CLOSE, param=params, data=datas)

    def cmd_close(self, flags1, flags2, tid, uid, mid, params,
                  data,errClass, errCode):
        ret, fid = self.fid_db.get_fid_from_filename(self.lastfilename)
        if ( fid == -1):
            print 'FID  not found for file %s'%self.lastfilename
        if ( self.fid_db.list_del_on_fid(fid) ):
            self.logger.log('File %s has been removed from FID list'
                            %(self.lastfilename))
        else:
            print 'Error: File  %s cannot be removed from the fid list. \n \
                          Debug the error ' %(self.lastfilename)
        self.fileoperation = 0
        self.testparser.readstop = 0

    def cmd_read_andx_request(self, cmd, readargs):
        offset_high = 0
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if ( len(readargs) <= 0 ):
            print 'File name missing for readfile command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    readargs)
        (status, fid, eof, alloc_size,
            filetype)=self.fid_db.get_fileinfo_on_filename(readargs[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(readargs[0])
            return
        
        if ( len(readargs) == 1):
            print 'Read entire file'
            start_offset = 0
            end_offset = eof
            tempeof = eof
            if (eof > 32768):
                while ( tempeof > 32768 ):
                    read_bytes = 32768
                    if ( start_offset > (1 << 32) ):
                        offset_high += start_offset - ( 1 << 32 )
                        start_offset = start_offset - ( 1 << 32)
                    self.read_andx_request(cmd, fid, offset_high, start_offset,
                                           read_bytes)
                    time.sleep(1)
                    start_offset += read_bytes
                    tempeof -= read_bytes
                self.read_andx_request(cmd, fid, offset_high, start_offset,
                                       tempeof)
            return

        if ( len(readargs) == 2):
            start_offset = eval(readargs[1])
            print 'Read remaining file from offset %ld to endoffset %ld'%(start_offset, eof)
            if (start_offset >= eof):
                return
            end_offset = eof
            tempeof = eof - start_offset
            if (eof > 32768):
                while (start_offset < end_offset and tempeof > 32768):
                    read_bytes = 32768
                    if ( start_offset > (1 << 32) ):
                        offset_high += start_offset - (1 << 32)
                        start_offset = start_offset - (1 << 32)
                    self.read_andx_request(cmd, fid, offset_high, start_offset,
                                           read_bytes)
                    time.sleep(1)
                    start_offset += read_bytes
                    tempeof -= read_bytes
                if (start_offset > eof):
                    return
                self.read_andx_request(cmd, fid, offset_high, start_offset,
                                       tempeof)
            return

        if ( len(readargs) == 3):
            start_offset = eval(readargs[1])
            end_offset = eval(readargs[2])

        if ( (start_offset > eof) and start_offset < 0 ):
            start_offset = 0

        if ( end_offset > eof):
            end_offset = eof

        if ( start_offset > (1<<32)):
            offset_high += start_offset - (1<<32)
            start_offset = start_offset - (1<<32)

        self.read_andx_request(cmd, fid, offset_high,
                               start_offset, end_offset)


    def read_andx_request(self,cmd, fid, offset_high,start_offset,end_offset):
        params = struct.pack('<ccHHLHHLHL', '\xff','0', 0, fid,
                             start_offset,end_offset, #max_count
                             0, # mincount
                             0, #reserved
                             0, # remaining
                             offset_high)
        # only 32bit number are supported at the moment
        datas =''
        self.fileoperation = 1
        self.send_smb_packet(cmd, param=params, data=datas)

    def cmd_read_andx(self, flags1, flags2, tid, uid, mid, params,
                      filedata,errClass, errCode):
        total_bytes_recv = 0
        (andx_cmd, _, andx_offset, remaining,
         data_compact_mode, _, data_len_low,
         data_offset,
         data_len_high,
         _,) = struct.unpack('<BBHHHHHHL6s', params)
        (bytecount,) = struct.unpack('<H', filedata[:2])
        padding = bytecount - data_len_low
        self.fileoperation = 0
        readdata = filedata[2+padding:]

##        if((len(readdata)) == data_len_low + data_len_high):
##            self.fileoperation = 0
##            self.testparser.readstop = 0
##            return
##        else:
##            total_bytes_recv += len(readdata)
##            while (total_bytes_recv < data_len_high + data_len_low):
##                pdb.set_trace()
##                self.testparser.readstop = 1
##                recv_data = self.client_socket.recv(RECV_BUFFER)
##                if not recv_data:
##                    continue;
##                total_bytes_recv += len(recv_data)
##                print len(recv_data)
               
        self.fileoperation = 0
        self.testparser.readstop = 0


    def cmd_write_andx_request(self, cmd, writeargs):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(writeargs) < 2 ):
            print 'File name missing for writefile command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,writeargs)
        (status, fid, eof,
        alloc_size,filetype) = self.fid_db.get_fileinfo_on_filename(writeargs[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(writeargs[0])
            return

        start_offset = eval(writeargs[1])
        if (start_offset < 0 ):
            start_offset = eof

        datas = ''

        if ( len(writeargs) > 3):
            clidata = writeargs[2:]
            for strings in clidata:
                datas += strings
                datas += ' '

        datas = datas[0:-1]
        self.write_andx_request(cmd,fid,start_offset,len(datas),datas)


    def write_andx_request(self, cmd, fid, start_offset, datalen, writedata):
        writemode = 00
        padding = '\x00'
        #len of smbheader + len of params till padding
        dataoffset = 32 + 31 + len(padding)
        params = struct.pack('<ccHHL4sHHHHHL', '\xff','0',0,fid,
                             start_offset,'ffffffff',writemode,
                             0, # remaining
                             0, #reserved
                             len(writedata), dataoffset, # need to calculate
                             0) #high_offset

        datas = "%c%s" %(0, writedata)
        self.fileoperation = 1
        self.send_smb_packet(cmd, param=params, data=datas)

    def cmd_write_andx(self, flags1, flags2, tid, uid, mid, params, filedata
                       ,errClass, errCode):
        (andx_cmd, _, andx_offset, count_low,
         remaining, cpunt_high, _,) = struct.unpack('<BBHHHHH', params)
        (bytecount,) = struct.unpack('<H', filedata[:2])
        self.fileoperation = 0


    def cmd_file_seek_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if  len(args) < 1 :
            print 'File name missing for seekfile command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        (status, fid, eof,
        alloc_size, filetype) = self.fid_db.get_fileinfo_on_filename(args[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(args[0])

        if ( len(args) == 1 ):
            offset = 0
            fileseek = SEEK_FILE_BEGINNING

        elif ( len(args) >= 2):
            fileseek = eval(args[1])
            if (fileseek < 0 or fileseek > 2 ):
                print 'Seek position incorrect for file %s' %args[0]
            if ( len(args) == 3):
                offset = eval(args[2])

        params = struct.pack('<HHL', fid, fileseek, offset)
        datas =''
        self.fileoperation = 1

        self.send_smb_packet(cmd, param=params, data= datas)


    def cmd_file_seek(self,flags1, flags2, tid, uid, mid, params,
                      data,errClass, errCode):
        (offset) = struct.unpack('<L', params)
        self.fileoperation = 0
        print 'TBD:Update the offset to the FID store'


    def cmd_check_dir_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if  len(args) < 1 :
            print 'directory name missing for isdir command'

        if ( len(args) == 1 ):
            if (self.capabilities_flags & CAP_UNICODE ):
                datas = '%c'%(0x04)
                unidirname = self.uniencoder(args[0]+'\0')[0]
                datas += unidirname
            else:
                datas = "%c%s\0" %( 0x04, args[0])
        self.fileoperation = 1
        self.send_smb_packet(SMB_CHECK_DIR, param='', data= datas)


    def cmd_check_dir(self,flags1, flags2, tid, uid, mid, params,
                      data,errClass, errCode):
        print 'It is a directory'
        self.fileoperation = 0


    def cmd_open_file_request(self, cmd, args):
        desired_access = 128
        search_attr = 135
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if  len(args) < 1 :
            print 'file name missing for openfile command'
        (self.errorclass,
         self.errorcode)=get_expected_error_value(self.capabilities_flags,args)

        if ( len(args) >=3 ):
            desired_access = eval(args[1])
            search_attr = eval(args[2])
        params = struct.pack('<HH', desired_access, search_attr)
        if (self.capabilities_flags & CAP_UNICODE ):
            unifilename = self.uniencoder(args[0]  + '\0')[0]
            datas = '%c'%(0x04)
            datas+=unifilename
        else:
            datas = '%c%s\0' %( 0x04, args[0] )
        self.lastfilename = args[0]

        tid = self.share_config_store.get_tid_from_share(self.shareinfo[0])
        if ( tid < 0 ):
            print ('Invalid share')
        fidlist = [ args[0], 0x0000, tid, 0, desired_access,
                    search_attr, 0, 0, 0, 0, 0, 0, 0,self.getfidno() ]

        if (self.fid_db.list_add(fidlist, 1)):
            print 'Openfile:FID added to config store'
        else:
            print 'Openfile:FID cannot be added to config store'
        self.fileoperation = 1
        self.send_smb_packet(SMB_OPEN, param=params, data=datas)


    def cmd_open_file(self,flags1, flags2, tid, uid, mid, params,
                      data,errClass, errCode):
        (fid, fileattr, lastwritetime,
         datasize,
         granted_access,) = struct.unpack('<HHLLH', params)

        (bytecount,) = struct.unpack('<H', data)

        if (self.fid_db.set_fid_on_filename(self.lastfilename, fid, 1)):
            print 'FID updated for file %s'%self.lastfilename
        else:
            print 'FID could not be updated for file %s'%self.lastfilename
        if (self.fid_db.set_fileinfo_on_filename(self.lastfilename,
                        datasize,datasize,0, 1,1) ):
            self.logger.log('Fileinfo added to fid')
        else:
            print 'Fileinfo not added to fid, error, file operation will fail'

        self.fileoperation = 0


    def cmd_read_file_request(self, cmd, readargs):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(readargs) <= 0 ):
            print 'File name missing for readfile command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    readargs)
        (status, fid, eof, alloc_size,
            filetype) = self.fid_db.get_fileinfo_on_filename(readargs[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(readargs[0])
        if ( len(readargs) == 1):
            print 'Read entire file'
            start_offset = 0
            end_offset = eof
            tempeof = eof
            while ( tempeof > 32768 ):
                read_bytes = 32768
                self.read_file_request(SMB_READ, fid, start_offset,read_bytes)
                time.sleep(1)
                start_offset += read_bytes
                tempeof -= read_bytes
            if (start_offset > eof):
                return
            self.read_file_request(SMB_READ, fid, start_offset, tempeof)
            return

        if ( len(readargs) == 2):
            start_offset = eval(readargs[1])
            end_offset = eof
            tempeof = eof - start_offset
            print 'Read file from offset %ld to %ld'%(start_offset, eof)
            if (start_offset >= eof):
                return
            while (start_offset < end_offset and tempeof > 32768):
                read_bytes = 32768
                self.read_file_request(SMB_READ, fid, start_offset,read_bytes)
                time.sleep(1)
                start_offset += read_bytes
                tempeof -= read_bytes
            self.read_file_request(SMB_READ, fid, start_offset, tempeof)
            return
            
        if ( len(readargs) == 3):
            start_offset = eval(readargs[1])
            count = eval(readargs[2])

        if ( (start_offset > eof) and start_offset < 0 ):
            start_offset = 0

        if ( count > eof):
            count = eof

        self.fileoperation = 1
        self.read_file_request(SMB_READ, fid, start_offset, count)


    def read_file_request(self, cmd, fid, start_offset, count):
        params = struct.pack('<HHLH',fid,count,start_offset,0) # remaining

        datas =''
        self.send_smb_packet(cmd, param=params, data=datas)


    def cmd_read_file(self, flags1, flags2, tid, uid, mid, params,
                      filedata,errClass, errCode):
        (count,_,) = struct.unpack('<H8s', params)
        (bytecount,bufferformat) = struct.unpack('<HB', filedata[:3])
        readdata = filedata[3:]
        self.fileoperation = 0


    def cmd_write_file_request(self, cmd, writeargs):
        offset = 0
        count = 0
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(writeargs) == 0 ):
            print 'File name missing for writefile command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    writeargs)
        (status, fid, eof, alloc_size,
        filetype) = self.fid_db.get_fileinfo_on_filename(writeargs[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(writeargs[0])

        if ( len(writeargs) == 1):
            filename = writeargs[0]
            offset = eof

        if ( len(writeargs) >=3):
            offset = eval(writeargs[1])
            if (offset < 0 ):
                offset = eof

        datas = ''

        if ( len(writeargs) > 3):
            clidata = writeargs[2:]
            for strings in clidata:
                datas += strings
                datas += ' '

        datas = datas[0:-1]
        self.fileoperation = 1
        self.write_file_request(SMB_WRITE,fid,offset,len(datas),datas)


    def write_file_request(self, cmd, fid, offset, datalen, writedata):
       params = struct.pack('<HHLH',
                             fid,
                             datalen,
                             offset,
                             0)# remaining

       datas = struct.pack('<BH', 0x01, datalen)
       datas += writedata
       self.send_smb_packet(cmd, param=params, data=datas)

    def cmd_write_file(self, flags1, flags2, tid, uid, mid, params,
                       filedata,errClass, errCode):
        (count,) = struct.unpack('<H', params)
        (bytecount,) = struct.unpack('<H', filedata[:2])
        self.fileoperation = 0

    def cmd_write_and_close_file_request(self, cmd, args):
        offset = 0
        count = 0
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if ( len(writeargs) == 0 ):
            print 'File name missing for writefile command'

        status, fid, eof, \
        alloc_size,
        filetype = self.fid_db.get_fileinfo_on_filename(writeargs[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(writeargs[0])

        if ( len(writeargs) == 1):
            filename = writeargs[0]
            offset = eof

        if ( len(writeargs) >=3):
            offset = eval(writeargs[1])
            if (offset < 0 ):
                offset = eof

        datas = ''

        if ( len(writeargs) > 3):
            clidata = writeargs[2:]
            for strings in clidata:
                datas += strings
                datas += ' '


        datas = datas[0:-1]
        self.fileoperation = 1
        self.write_file_request_wc6(cmd,fid,offset,len(datas),datas)

    def write_and_close_file_request_wc6(self, cmd, fid, offset, datalen,
                                         writedata):
        pad = 0
        params = struct.pack('<HHL8sH',fid,datalen,offset,lastwritetime)
        datas = struct.pack('<HB', len(pad)+datalen,0x01)
        datas += writedata
        self.send_smb_packet(cmd, param=params, data=datas)


    def write_and_close_file_request_wc12(self, cmd, fid, offset, datalen,
                                          writedata):
        pad = 0
        params = struct.pack('<HHL8sHLLL',fid,datalen,offset,lastwritetime,
                                 0,0,0)
        datas = struct.pack('<HB', len(pad)+datalen,0x01)
        datas += writedata
        self.send_smb_packet(cmd, param=params, data=datas)

    def cmd_write_and_close_file(self, flags1, flags2, tid, uid, mid,
                                 params, filedata,errClass, errCode):
        (count,) = struct.unpack('<H', params)
        (bytecount,) = struct.unpack('<H', filedata[:2])
        self.fileoperation = 0

    def cmd_delete_dir_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(args) == 0 ):
            print 'Provide the name of directory/file to be deleted'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if (self.capabilities_flags & CAP_UNICODE ):
            datas = '%c'%(0x04)
            unidirname = self.uniencoder(args[0]+'\0')[0]
            datas += unidirname
        else:
            datas = '%c%s\0' %(0x04, args[0])

        self.fileoperation = 1
        self.send_smb_packet(SMB_DELETE_DIR, param='', data=datas)


    def cmd_delete_dir(self, flags1, flags2, tid, uid, mid, params,
                       data,errClass, errCode):
        print 'directory deleted'
        self.fileoperation = 0


    def cmd_delete_file_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        search_attr = 0
        if ( len(args) == 0 ):
            print 'Provide the name of directory/file to be deleted'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if ( len(args) == 1):
            search_attr = 3
        elif ( len(args) == 2 ):
            search_attr = eval(args[1])

        params = struct.pack('<H', search_attr)
        if (self.capabilities_flags & CAP_UNICODE ):
            datas = '%c'%(0x04)
            unifilename = self.uniencoder(args[0]+'\0')[0]
            datas += unifilename
        else:
            datas = '%c%s\0' %(0x04, args[0] )

        self.fileoperation = 1
        self.send_smb_packet(SMB_DELETE, param=params, data=datas)

    def cmd_delete_file(self, flags1, flags2, tid, uid, mid, params,
                        data,errClass, errCode):
        print 'file deleted'
        self.fileoperation = 0


    def cmd_rename_request(self, cmd, args ):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if ( len(args) == 0  and len(args) < 2):
            print 'Missing arguments for rename command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        #By default the search attributes are set to look at
        # hidden files, systems files, include directories in searching
        params = struct.pack('<H', 0x0016)
        if (self.capabilities_flags & CAP_UNICODE ):
            datas = '%c'%(0x04)
            datas += self.uniencoder(args[0]+'\0')[0]
            datas += '%c'%(0x04) + '\0'
            datas += self.uniencoder(args[1]+'\0')[0]
        else:
            datas = '%c%s\0%c%s\0' %(0x04, args[0], 0x04, args[1])

        self.fileoperation = 1
        self.send_smb_packet(SMB_RENAME, param=params, data=datas)

    def cmd_rename(self, flags1, flags2, tid, uid, mid, params,
                   data,errClass, errCode):
        print 'Rename completed'
        self.fileoperation = 0


    def cmd_create_dir(self, flags1, flags2, tid, uid, mid, params,
                       data,errClass, errCode):
        print 'Created directory'
        self.fileoperation = 0

    def cmd_create_dir_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if ( len(args) == 0 ):
            print 'Provide the name of directory to be created'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if (self.capabilities_flags & CAP_UNICODE ):
            datas = '%c'%(0x04)
            unidirname = self.uniencoder(args[0]+'\0')[0]
            datas += unidirname
        else:
            datas = '%c%s\0' %(0x04, args[0])

        self.fileoperation = 1
        self.send_smb_packet(SMB_CREATE_DIR, param='', data=datas)


    def cmd_flush_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or
                self.fileoperation):
            time.sleep(1)

        if ( len(args) == 0 ):
            #Flush all the files from this client
            fid = -1
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if ( len(args) == 1):
            status, fid = self.fid_db.get_fid_from_filename(args[0])
            if ( status ==  0 ):
                print 'Unable to find the fid of the given file, because \
                       the file is not open'

        params = struct.pack('<H', fid)
        self.fileoperation = 1

        self.send_smb_packet(SMB_FLUSH, param=params, data='')


    def cmd_flush(self, flags1, flags2, tid, uid, mid, params, data,
                  errClass, errCode):
        print 'Flush of file successful'
        self.fileoperation = 0


    def cmd_move_file_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(args) <= 1 ):
            print 'Arguments missing for command movefile'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        tid = -1
        flags = 0
        # Currently move from only same tree is permitted
        if ( len(args) > 3):
            if ( cmp(args[0], 'file') == 0 ):
                flags = 0 | 1
            elif( cmp(args[0], 'dir')  == 0):
                flags = 1

        oldname = args[1]
        newname = args[2]
        params = struct.pack('<hHH', 0xfffe, 0x32, 1)#flags)
        if ( self.cli_flags2 & FLAGS2_UNICODE ):
            print 'Unicode not implemented'
        else:
            datas = '%c%s\0%c%s\0' %(0x04, oldname, 0x04, newname)

        self.fileoperation = 1
        self.send_smb_packet(cmd, param=params, data=datas)


    def cmd_move_file(self, flags1, flags2, tid, uid, mid, params,
                      data,errClass, errCode):
        (count,) = struct.unpack('<H', params)
        (bytecount, err_file_fmt,) = struct.unpack('<HB', filedata[:3])
        err_filename = filedata[3:]
        print 'Number of files moved = %d' %count
        self.fileoperation = 0

    def cmd_copy_file_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(args) <= 1 ):
            print 'Arguments missing for command movefile'

        tid = -1
        flags = 0x10

        # Currently move from only same tree is permitted
        if ( len(args) > 3):
            if ( cmp(args[0], 'file') == 0 ):
                flags|= 0x01
        #    elif( cmp(args[0], 'dir')  == 0):
         #       flags = 0x02
        oldname = args[1]
        newname = args[2]

        params = struct.pack('<HHH', tid, 0x10, flags)
        if ( self.cli_flags2 & FLAGS2_UNICODE ):
            print 'Unicode not implemented'
        else:
            datas = '%c%s\0%c%s\0' %(0x04, oldname, 0x04, newname)

        self.fileoperation = 1
        self.send_smb_packet(cmd, param=params, data=datas)


    def cmd_copy_file(self, flags1, flags2, tid, uid, mid, params,
                      data,errClass, errCode):
        (count,) = struct.unpack('<H', params)
        (bytecount, err_file_fmt,) = struct.unpack('<HB', filedata[:3])
        err_filename = filedata[3:]
        print 'Number of files moved = %d' %count
        self.fileoperation = 0

    def cmd_change_dir_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if ( len(args) == 0 ):
            print 'Arguments missing for command change directory'

        self.nt_create_andx_request(args[0],  0x10, 0x00100001,
                               0x00, 0x07, 1, 1, 2, 0)

    def nt_trans_request(self, subcmdcount, subcmd, level_of_interest,
                         param, data, searchid=0 , max_data_count=1024,
                         max_setup_count = 0, max_param_count = 10,
                         flags = 0x00):
        while(self.client_state < CONNECTED_TO_SHARE or
            (self.fileoperation and subcmd != TRANS2_FIND_NEXT2)):
            time.sleep(1)
##        while(self.fileoperation and subcmd != TRANS2_FIND_NEXT2):
##            time.sleep(1)

        padlen = 0
        param_offset = SMB_HEADER_LEN + 36
        if ( len(data) == 0 ):
            data_offset = 0
        else:
            data_offset = param_offset + len(param)

        trans2req = struct.pack('<HHHHBBHLHHHHHBBH',
                                len(param), len(data),
                                max_param_count, #10
                                max_data_count,
                                max_setup_count, #max setup count
                                0, #reserved
                                0, #flags
                                0, #time out
                                0, # reserved
                                len(param),
                                param_offset, #need to calculate this
                                len(data),
                                data_offset, #data offset
                                subcmdcount,
                                0,
                                subcmd) #reserved

        if ((len(trans2req) + 2)/2 ):
            padlen = 3
            remain_req = '\0' * padlen
            remain_req += param

        #Add padding after parameter
        if ( len(data) and level_of_interest != SMB_SET_FILE_DISPOSITION_INFO):
            #parm_pad_len = (len(param) % 4)
            parm_pad_len = 3
            remain_req += '\0' * parm_pad_len
            remain_req += data
        else:
            remain_req += data

        self.fileoperation = 1
        self.send_smb_packet(SMB_TRANSACTION2, param=trans2req,
                             data=remain_req,error=0,subcmd = subcmd,
                             level_of_interest=level_of_interest,
                             sid=searchid)


    def cmd_trans2(self, flags1, flags2, tid, uid, mid, params,
                   data,errClass, errCode):
        (totalParamCount, totalDataCount, _, paramCount, paramOffset, paramds,
         dataCount, dataOffset, datads, setupCount, _) \
         = struct.unpack('<HHHHHHHHHBB', params[:20])
        moreFragments = ((paramCount + paramds < totalParamCount) or
                   (dataCount + datads < totalDataCount))
        #if ( moreFragments ):
        #    print 'Fragmented trans2 response sent by server. Fragmented \
        #            response not yet supported'

##        +2 = bytecount len, +1 = param offset start from 0
        padlen = paramOffset - (SMB_HEADER_LEN + TRANS2_RESP_LEN + 2 + 1 )

##      Parameter offset in the data
        paramOffsetstart = paramOffset - (SMB_HEADER_LEN + TRANS2_RESP_LEN +
                                          2 + 1 + padlen)
        paramOffsetend = paramOffsetstart + paramCount
        padafterparam = (dataOffset - ( paramOffset + paramCount) )
        dataOffsetstart = paramOffsetend + padafterparam
        status, trans2req = get_value_from_request_list(self.transactions2,
                                                        mid)
        if ( status == 0 ):
            #print 'Lookup failed for Trans2 request for mid = %d'%(mid)
            #status = 0
            junk =0
        else:
            tmid = trans2req.keys()[0]
            translist = trans2req.get(tmid)
            loi = self.get_trans2_response_parser(translist[2] ,
                                                  translist[3])
            print loi.__name__
            bcandpad = 2 + padlen
            trans2param = data[(paramOffsetstart + bcandpad) :
                               (paramOffsetend + bcandpad)]
            trans2data = data[(dataOffsetstart + bcandpad) :
                              (dataOffsetstart + dataCount + bcandpad)]
            loi(trans2param, trans2data)

        if ( self.transactions2.has_key(mid)):
            self.transactions2.pop(mid)

        self.fileoperation = 0

    def build_queryfs_request(self, subcmd, loi):
        max_data_count = 1024
        params = struct.pack('<H',loi)
        self.nt_trans_request( 1,  subcmd, loi, params, data ='')


    def cmd_trans2_queryfs_info_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        subcmd = TRANS2_QUERY_FS_INFORMATION
        if ( len(args) == 0):
            loi = SMB_QUERY_FS_VOLUME_INFO
            print 'No level of intereset passed to getpathinfo, \
                    defaulting to SMB_QUERY_FS_VOLUME_INFO'

        elif ( len(args) >= 1):
            loi = g_get_queryfs_loi_from_string(args[0])
            if ( loi == -1 ):
            	loi = SMB_QUERY_FS_VOLUME_INFO
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                                     args)
        self.build_queryfs_request(subcmd, loi)

    def cmd_trans2_get_fsalloc_info(self, params, data):
        (fs_id,  sec_per_unit, totalunits,
         available_units, bytes_per_sec,) = struct.unpack('<LLLLH', data)

    def cmd_trans2_get_vol_info(self, params, data):
        (vol_sl_no,  volname_len,) = struct.unpack('<LB', data[0:5])
        volname = data[5:volname_len]

    def cmd_trans2_get_fsvol_info(self, params, data):
        (vol_creation_time, vol_sl_no,  volname_len,
         _, ) = struct.unpack('<8sLLH', data[0:18])
        volname = data[18:volname_len]

    def cmd_trans2_get_fssize_info(self, params, data):
        (total_alloc_units, free_alloc_units, sec_per_unit,
         num_bps, ) = struct.unpack('<8s8sLL', data)

    def cmd_trans2_get_fsdev_info(self, params, data):
        (dev_type, dev_chars, ) = struct.unpack('<LL', data[0:8])

    def cmd_trans2_get_fsattr_info(self, params, data):
        (fs_attr, fs_comp_len,
         fs_name_len, ) = struct.unpack('<LLL', data[0:12])
        fsname = data[12:fs_name_len]

    def cmd_trans2_get_fs_fullsize_info(self, params, data):
        (tot_alloc_size,caller_free_alloc_units,
         free_alloc_units, sec_per_unit,
         num_bps ) = struct.unpack('<8s8s8sLL', data[0:32])


#TRANS2_QUERY_PATH_INFO commands and all information level
    def build_querypathinfo_request(self, subcmd, level_of_interest,
                                    filename):
        params = struct.pack('<HL', level_of_interest, 0)
        if (self.capabilities_flags & CAP_UNICODE):
            filename = self.uniencoder(filename+'\0')[0]
            params += filename
        else:
            filename += '\0'
            params += filename
        self.nt_trans_request( 1,  subcmd, level_of_interest,
                               param=params, data ='')

    def cmd_trans2_querypath_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        subcmd = TRANS2_QUERY_PATH_INFORMATION
        if ( len(args) == 0):
            print 'No arguments passed to getpathinfo'
            return

        elif ( len(args) == 1):
            loi = SMB_QUERY_FILE_BASIC_INFO
            print 'No level of intereset passed to getpathinfo, \
                    defaulting to SMB_QUERY_FILE_BASIC_INFO '

        elif ( len(args) >= 2):
            loi = g_get_querypath_loi_from_string(args[1])
            if ( loi == -1 ):
                loi = SMB_QUERY_FILE_BASIC_INFO
                print 'Level of intereset argument is not available \
                        in getpathinfo, defaulting to \
                        SMB_QUERY_FILE_BASIC_INFO '
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)

        self.build_querypathinfo_request(subcmd, loi, args[0])


    def cmd_trans2_get_path_std_info(self, params, data):
        (alloc_size, eof, no_of_links, delete_pending,
         dir,) = struct.unpack('<8s8sLBB', data[0:22])

    def cmd_trans2_get_path_file_basic_info(self, params, data):
        (ctime, atime, wtime, mtime, extfileattr,
        pad,) = struct.unpack('<8s8s8s8sLL', data[0:40])

    def cmd_trans2_get_path_file_std_info(self, params, data):
        (alloc_size, eof, no_of_links, delete_pending,
         dir,) = struct.unpack('<8s8sLBB', data[0:22])

    def cmd_trans2_get_path_file_ea_info(self, params, data):
        (ea_size,) = struct.unpack('<L', data[0:4])

    def cmd_trans2_get_path_file_name_info(self, params, data):
        (fnlen,) = struct.unpack('<L', data[0:4])
        filename = data[4:fnlen]

    def cmd_trans2_get_path_file_alloc_info(self, params, data):
        (alloc_size,) = struct.unpack('<8s', data[0:8])

    def cmd_trans2_get_path_file_eof_info(self, params, data):
        (eof,) = struct.unpack('<8s', data[0:8])

    def cmd_trans2_get_path_file_all_info(self, params, data):
        (ctime, atime, wtime, chtime, ext_file_attr, alloc_size,
         eof, no_of_links, delete_pending, dir, indexno,
         easize, accessflags, indexno2, cur_byte_offset,
         mode, align_req,
        fnlen, ) = struct.unpack('<8s8s8s8sH8s8sLBB8sLL8s8sLLL',
                                 data[0:100])
        filename = data[96:fnlen]

    def cmd_trans2_get_path_file_altname_info(self, params, data):
        (fnlen,) = struct.unpack('<L', data[0:4])

    def cmd_trans2_get_path_file_stream_info(self, params, data):
        (nxt_ent_offset, stream_name_len, streamsize,
         stream_alloc_size,) = struct.unpack('<LL8s8s', data[0:24])
        stream_name = data[24:stream_name_len]

    def cmd_trans2_get_path_file_compress_info(self, params, data):
        (comp_file_size, comp_fmt, comp_unit_sft, chunk_sft,
         cluster_sft,) = struct.unpack('<8sHBBB', data[0:13])

    def cmd_trans2_get_path_file_internal_info(self, params, data):
        (index_no,) = struct.unpack('<8s', data[0:8])

    def cmd_trans2_get_path_file_nw_open_info(self, params, data):
        (ctime, atime, wtime, chtime,
             allocsize, eof, extfileattr,
         _,) = struct.unpack('<8s8s8s8s8s8sLL', data[0:56])

# TRANS2_FIND_FIRST2 and its loi
    def build_findfirst2_request(self, subcmd, loi, searchid, pattern):
        #By default the search attributes are set to 0x0016 - hidden,
        #system, directory
        #Flags are set to 0x0006 -  resume, close on EOS
        #storage type - 0
        #Searchcount is set to 1366
        search_attr = 0x0016
        flags = 0x0006
        storage_type = 0
        search_count = 1366
        params = struct.pack('<HHHHL', search_attr, search_count, flags,
                             loi, storage_type)
        if (self.capabilities_flags & CAP_UNICODE):
            unipattern = self.uniencoder(pattern+'\0')[0]
            params+= unipattern
        else:
            pattern += '\0'
            params += pattern
        self.nt_trans_request(1,subcmd,loi,param=params, data ='',
                              searchid=searchid, max_data_count = 6144)

    def build_queryfileinfo_request(self, subcmd, loi, openfid):
        max_data_count = 1024
        params = struct.pack('<HH',openfid, loi)
        self.nt_trans_request( 1,  subcmd, loi, params, data ='')

    def cmd_trans2_queryfile_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        subcmd = TRANS2_QUERY_FILE_INFORMATION
        if ( len(args) == 0):
            print 'No arguments passed to queryfileinfo'
            return

        elif ( len(args) == 1):
            loi = SMB_FIND_FILE_BOTH_DIRECTORY_INFO
            filename = args[0]
            print 'No level of intereset passed to findfirst2, \
                    defaulting to SMB_FIND_FILE_BOTH_DIRECTORY_INFO '

        elif ( len(args) >= 2):
            filename = args[0]
            loi = g_get_querypath_loi_from_string(args[1])
            if ( loi == -1 ):
                loi = SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                print 'Level of intereset argument is not available \
                        in findfirst2, defaulting to \
                        SMB_FIND_FILE_BOTH_DIRECTORY_INFO '
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                                     args)
        (status, openfid, eof, alloc_size,
        filetype) = self.fid_db.get_fileinfo_on_filename(filename)
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(args[0])
            return

        self.build_queryfileinfo_request(subcmd, loi, openfid)

    def cmd_trans2_findfirst2_request(self, cmd, args):
        subcmd = TRANS2_FIND_FIRST2
        self.testparser.readstop = 1
        if ( len(args) == 0):
            loi = SMB_FIND_FILE_BOTH_DIRECTORY_INFO
            pattern = '\*'
            print 'No arguments passed to findfirst2, defaulting to \
                   find pattern \' \* \" \n and the level of interest \
                   to SMB_FIND_FILE_BOTH_DIRECTORY_INFO '

        elif ( len(args) == 1):
            loi = SMB_FIND_FILE_BOTH_DIRECTORY_INFO
            print 'No level of intereset passed to findfirst2, \
                    defaulting to SMB_FIND_FILE_BOTH_DIRECTORY_INFO '

        elif ( len(args) >= 2):
            pattern = args[0]
            loi = g_get_findfirst2_loi_from_string(args[1])
            patternlist = [ 0, pattern ]
            self.ff2_sid_list.append(patternlist)
            if ( loi == -1 ):
                loi = SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                print 'Level of intereset argument is not available \
                        in findfirst2, defaulting to \
                        SMB_FIND_FILE_BOTH_DIRECTORY_INFO '
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        self.ff2_sid_list.append([0, pattern])
        self.build_findfirst2_request(subcmd, loi, 0, pattern)

    def listfiles_find_filedir_both_info(self, searchcount, searchid,
                                         eos, data):
        dataindex = 0
        filedata = data
        cnt = 0
        while (cnt < searchcount):
            if ( len(filedata) < 70 ):
                return
            (nxt_entry_offset, fileindex,  crtime, atime, ctime,
             chtime, eof, allocsize, fileattr, filenamelen,
             ealistlen, shortfnlen,
             _,) = struct.unpack('<LL8s8s8s8s8s8sLLLBB',
                                 filedata[dataindex:dataindex+70])
            shortfilename = filedata[(dataindex+70):
                                     (dataindex+70+shortfnlen)]
            dataindex = dataindex + 70 + shortfnlen + (24 - shortfnlen)
            filename = filedata[dataindex: (dataindex + filenamelen)]
            filedata = filedata[nxt_entry_offset:]
            dataindex = 0
            cnt += 1
            print filename,  date_time_from_epoch(crtime)
            if ((nxt_entry_offset ==0 or len(filedata) < nxt_entry_offset)
                        and (eos == 0)):
                self.build_findnext2_request(searchid,
                                    SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
                                    filename)
                break


    def cmd_trans2_findfirst2_find_filedir_both_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0
        self.listfiles_find_filedir_both_info(searchcount,searchid,eos,data)

    def listfiles_file_dir_info(self, searchcount, searchid, eos, data):
        dataindex = 0
        cnt = 0
        filedata = data
        while (cnt < searchcount):
            ( nxt_entry_offset, fileindex, crtime, atime, ctime,
              chtime, eof, allocsize,fileattr,
              filenamelen,) = struct.unpack('<LL8s8s8s8s8s8sLL',
                                   filedata[dataindex:dataindex+64])
            filename = filedata[(dataindex+64):
                                    (dataindex+64+filenamelen)]
            dataindex = nxt_entry_offset
            filedata = filedata[dataindex:]
            dataindex = 0
            cnt += 1
            print filename,  date_time_from_epoch(crtime)
            if ((len(filedata) < nxt_entry_offset) and (eos == 0)):
                print 'Sending trans2findnext filedirinfo request'
                self.build_findnext2_request(searchid,
                           SMB_FIND_FILE_DIRECTORY_INFO, filename)
                break

    def cmd_trans2_findfirst2_file_dir_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0
        self.listfiles_file_dir_info(searchcount, searchid, eos, data)


    def listfiles_file_full_dir_info(self, searchcount, searchid,
                                     eos, data):
        dataindex = 0
        cnt = 0
        filedata = data
        while (cnt < searchcount):
            ( nxt_entry_offset, fileindex, crtime, atime, ctime,
              chtime, eof, allocsize, extfileattr, filenamelen,
              easize,) = struct.unpack('<LL8s8s8s8s8s8sLLL',
                                   filedata[dataindex:dataindex+68])
            filename = filedata[(dataindex+68):
                                (dataindex+68+filenamelen)]
            dataindex = nxt_entry_offset
            filedata = filedata[dataindex:]
            dataindex = 0
            cnt += 1
            print filename,  date_time_from_epoch(crtime)
            if ((len(filedata) < nxt_entry_offset) and (eos == 0)):
                print 'Sending trans2findnext fulldirinfo request'
                self.build_findnext2_request(searchid,
                            SMB_FIND_FULL_BOTH_DIRECTORY_INFO, filename)
                break

    def cmd_trans2_findfirst2_file_full_dir_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0
        self.listfiles_file_full_dir_info(searchcount, searchid, eos, data)


    def listfiles_filenames_info (self,searchcount, searchid, eos, data):
        dataindex = 0
        cnt = 0
        filedata = data
        while (cnt < searchcount):
            ( nxt_entry_offset, fileindex,
            filenamelen,) = struct.unpack('<LLL',
                               filedata[dataindex:dataindex+12])
            filename = filedata[(dataindex+12):
                                (dataindex+12+filenamelen)]
            dataindex = nxt_entry_offset
            filedata = filedata[dataindex:]
            dataindex = 0
            cnt += 1
            print filename
            #build findnext2 request if eos is not set to 1
            if ((len(filedata) < nxt_entry_offset) and (eos == 0)):
                print 'Sending trans2findnext filenamesinfo request'
                self.build_findnext2_request(searchid,
                            SMB_FIND_FILE_NAMES_INFO, filename)
                break

    def cmd_trans2_findfirst2_filenames_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0
        self.listfiles_filenames_info(searchcount, searchid, eos, data)


    def listfiles_find_fileiddir_info (self,searchcount, searchid,
                                       eos, data):
        dataindex = 0
        cnt = 0
        filedata = data
        while (cnt < searchcount):
            (nxt_entry_offset, fileindex,  crtime, atime, ctime,
             chtime, eof, allocsize, extfileattr, filenamelen,
             ealistlen, fileid,_) = struct.unpack('<LL8s8s8s8s8s8sLLL8sL',
                                     filedata[dataindex:dataindex+80])
            filename = filedata[(dataindex+80):
                                (dataindex+80+filenamelen)]
            dataindex = nxt_entry_offset
            filedata = filedata[dataindex:]
            dataindex = 0
            cnt += 1
            print filename, date_time_from_epoch(crtime)
            if ((len(filedata) < nxt_entry_offset) and (eos == 0)):
            	print 'Sending trans2findnext fileiddirinfo request'
            	self.build_findnext2_request(searchid,SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO,filename)
            	break

    def cmd_trans2_findfirst2_find_fileiddir_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0

        self.listfiles_find_fileiddir_info(searchcount, searchid, eos, data)


    def listfiles_find_fileiddir_both_info(self, searchcount, searchid,
                                           eos, data):
        dataindex = 0
        cnt = 0
        filedata = data
        while (cnt < searchcount):
            (nxt_entry_offset, fileindex,  crtime, atime, ctime,
             chtime, eof, allocsize, fileattr, filenamelen,
             ealistlen, shortfnlen, _,) = struct.unpack('<LL8s8s8s8s8s8sLLLBB',
                                     filedata[dataindex:dataindex+70])
            shortfilename = filedata[(dataindex+70):
                                     (dataindex+70+shortfnlen)]
            dataindex = dataindex + 70 + shortfnlen + (24 - shortfnlen)

            (_, file_id,) = struct.unpack('<H8s',
                                   filedata[dataindex:(dataindex+10)])
            dataindex = dataindex + 10
            filename = filedata[dataindex: (dataindex + filenamelen)]
            dataindex = nxt_entry_offset
            filedata = filedata[dataindex:]
            dataindex = 0
            cnt += 1
            print filename,  date_time_from_epoch(crtime)
            #build findnext2 request if eos is not set to 1
            if ((len(filedata) < nxt_entry_offset) and (eos == 0)):
                print 'Sending trans2findnext bothfileiddirinfo request'
                self.build_findnext2_request(searchid,
                         SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO, filename)
                break

    def cmd_trans2_findfirst2_find_fileiddir_both_info(self, params, data):
        (searchid, searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHHH', params[0:10])
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        if ( searchid ):
            lastpattern[0] = searchid
        if ( eos == 0 ):
            self.testparser.readstop = 1
        else:
            self.testparser.readstop = 0
        self.listfiles_find_fileiddir_both_info(searchcount, searchid,
                                                eos, data)

    def cmd_not_implemented(self, params, data):
        print 'Not implemented, not used in latest clients'

# TRANS2_FIND_NEXT2 and its loi
    def build_findnext2_request(self, searchid, fnloi, last_filename_seen):
        #By default the search attributes are set to 0x0016 - hidden,
        #system, directory
        #Flags are set to 0x0006 -  resume, close on EOS
        #storage type - 0
        #Searchcount is set to 1366
        search_attr = 0x0016
        flags = 0x0006
        storage_type = 0
        subcmd = TRANS2_FIND_NEXT2
        search_count = 1366
        fnparams = struct.pack('<HHHLH', searchid, search_count, fnloi,
                             0, flags)
        if (self.capabilities_flags & CAP_UNICODE):
            fnparams+= last_filename_seen + '\0\0'
        else:
            fnparams += last_filename_seen

        self.fileoperation = 0
        self.nt_trans_request( 1,  subcmd, fnloi, param=fnparams, data ='',
                               searchid=searchid, max_data_count = 6144)

##TRANS2_FIND_NEXT2 Repsonse parsing
    def cmd_trans2_findnext2_find_filedir_both_info(self, params, data):
        if (len(params) < 8):
            return
        (searchcount,eos, ea_err_offset,
             last_name_offset, ) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_find_filedir_both_info(searchcount, lastpattern[0],
                                              eos, data)

    def cmd_trans2_findnext2_find_file_dir_info(self, params, data):
        if ( len(params) < 8 ):
            return
        (searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_file_dir_info(searchcount, lastpattern[0], eos, data)

    def cmd_trans2_findnext2_find_file_full_dir_info(self, params, data):
        if ( len(params) < 8 ):
            return
        (searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_file_full_dir_info(searchcount, lastpattern[0], eos, data)

    def cmd_trans2_findnext2_find_filenames_info(self, params, data):
        if ( len(params) < 8 ):
            return
        (searchcount, eos, ea_err_offset,
         last_name_offset) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_filenames_info(searchcount, lastpattern[0], eos, data)

    def cmd_trans2_findnext2_find_fileiddir_info(self, params, data):
        if ( len(params) < 8 ):
            return
        (searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_find_fileiddir_info(searchcount, lastpattern[0], eos, data)

    def cmd_trans2_findnext2_find_fileiddir_both_info(self, params, data):
        if ( len(params) < 8 ):
            return
        (searchcount, eos, ea_err_offset,
         last_name_offset, ) = struct.unpack('<HHHH', params[0:8])
        if ( eos ):
            self.testparser.readstop = 0
        else:
            self.testparser.readstop = 1
        lastpattern = self.ff2_sid_list[len(self.ff2_sid_list)-1]
        self.listfiles_find_fileiddir_info(searchcount, lastpattern[0],
                                           eos, data)

#TRANS2 Close request

    def get_findfirst_sid_list(self, args):
        sidlist = []
        if ( len(args) == 0):
            for pattern in self.ff2_sid_list:
                sidlist.append(pattern[0])
        else:
            for pattern in self.ff2_sid_list:
                if ( cmp(args[0], pattern[1]) == 0):
                    sidlist.append(pattern[0])

        return sidlist


    def build_trans2_close(self,cmd,argslen, args):
        if ( argslen ):
            for sid in args:
                params = struct.pack('<H', sid)
                self.send_smb_packet(cmd, param=params, data='')

    def cmd_find_close2_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if ( len(args) == 0 ):
            print 'Search pattern not mentioned, Closing all the searchid'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        sidlist = self.get_findfirst_sid_list(args)
        self.build_trans2_close(cmd, len(sidlist), sidlist)

    def cmd_find_close2(self, flags1, flags2, tid, uid, mid,
                               params, data,errClass, errCode):
        self.ff2_sid_list = self.ff2_sid_list[:-1]


#TRANS2_SET_FILE_INFO
    def build_setinfo_request(self, subcmd, loi, num_of_args, fid, args):
        num_msb = 0
        num_lsb = 0
        datas = ''
        params = struct.pack('<HHH', fid, loi, 0)

        if ( loi == SMB_SET_FILE_DISPOSITION_INFO):
            datas = struct.pack('<B', 1)

        elif ( loi == SMB_SET_FILE_END_OF_FILE_INFO or
             loi == SMB_SET_FILE_ALLOCATION_INFO):
            datas = struct.pack('<LL', num_msb,num_lsb)

        else:
            print 'Not implemented time and date functions in setfileinfo'
            crtime_msb = 0
            crtime_lsb = 0
            atime_msb = 0
            atime_lsb = 0
            wtime_msb = 0
            wtime_lsb = 0
            chtime_msb = 0
            chtime_lsb = 0
            extfileattr = 0
            pad = 0
            datas = struct.pack('LLLLLLLLLL', crtime_msb, crtime_lsb,
                                atime_msb, atime_lsb, wtime_msb,
                                wtime_lsb, chtime_msb, chtime_lsb,
                                extfileattr, pad)
        self.nt_trans_request(1, subcmd, loi, param=params,
                              data=datas)


    def cmd_trans2_setfile_info_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)

        if (len(args)  == 0):
            print 'Argument missing for setfileinfo command'

        if ( len(args) == 1):
            print 'Specify the level of information to be updated along with \
                     its arguments'

        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        (status, fid, eof, alloc_size,
        filetype,) = self.fid_db.get_fileinfo_on_filename(args[0])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(args[0])
        (loi, num_of_args) = g_get_setfile_loi_from_string(args[1])
        self.build_setinfo_request(TRANS2_SET_FILE_INFORMATION,
                                   loi, num_of_args, fid, args)


    def cmd_generic_response(self,flags1, flags2, tid, uid, mid, params,
                             data,errClass, errCode):
    #def cmd_generic_response(self, param, data):
        print 'Command executed Successfully'
        self.fileoperation = 0

    def cmd_trans2_create_dir_request(self, cmd, args):
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        if (len(args)  == 0):
            print 'Argument missing for trans2createdir command'
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        params = struct.pack('<L', 0)
        if (self.capabilities_flags & CAP_UNICODE):
            unidirname = self.uniencoder(args[0]+'\0')[0]
            params += unidirname
        else:
            params+=args[0] + '\0'

        self.nt_trans_request(1, TRANS2_CREATE_DIRECTORY, 1000, param=params,
                    data='')

    def cmd_trans2_create_dir(self, params, data):
        (eaval,) = struct.unpack('<H', params[:2])

#LOCK BYTE RANGE/UNLOCK BYTE RANGE
    def build_lockunlockbyterange(cmd, fid, startoffset, bytestolock):
        params = datas = ''
        params = struct.pack('<HLL', fid, bytestolock, startoffset)

        self.send_smb_packet(cmd, param=params, data=datas)
        self.fileoperation = 1

    def cmd_lockunlockbyterange_request(self, cmd, args):
        lock = 0
        read = 0
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)

        if ( cmd == SMB_LOCK_BYTE_RANGE):
            lock = 1
            read = 0

        elif ( cmd == SMB_UNLOCK_BYTE_RANGE):
            lock = 0
            read = 0

        elif ( cmd == SMB_LOCK_AND_READ):
            lock = 1
            read = 1

        elif ( cmd == SMB_WRITE_AND_UNLOCK):
            lock = 0
            read = 2
            if ( len(args) == 3 ):
                writebuflen = 65530
                writebuf = A * 65530

        if (len(args)  == 0):
            print 'Argument missing for lockbytes command'

        if ( len(args) == 1):
            (status, fid, eof, alloc_size,
             filetype)=self.fid_db.get_fileinfo_on_filename(args[0])
            if ( status == 0):
                print 'Unable to retireve information for file %s' %(args[0])
                print 'Byte ranges to lock/unlock not specified.\
                Locking complete file'
                startoffset = 0
                bytestolock = eof

            if ( len(args) == 2):
                startoffset = eval(args[1])
                bytestolock = eof - startoffset
            else:
                startoffset = eval(args[1])
                bytestolock = eval(args[2])

# TODO - Store the lock ranges on the file
        if ( (lock and read == 0) or (lock==0 and read==0)):
            self.build_lockunlockbyterange(cmd, lock, fid,  startoffset,
                                           bytestolock)
        elif(read and lock):
            self.build_lockandread(cmd, lock, fid, startoffset, bytestolock)

        elif(read==2 and lock==0):
            self.build_writeandunlock(cmd, fid, startoffset, bytestolock,
                                      writebuflen, writebuf)

    def cmd_lockandread(self,flags1, flags2, tid, uid, mid, params,
                        data,errClass, errCode):
        (bytesreturned,_,) = struct.unpack('<H8s', params[:10])
        (byte_count,bufformat,datacnt,) = struct.unpack('<HBH', data[:5])
        readdata = data[5:datacnt]
        self.fileoperation = 0


    def cmd_writeandunlock(self,flags1, flags2, tid, uid, mid,params,
                           data,errClass, errCode):
        (byteswritten) = struct.unpack('<H', params)
        self.fileoperation = 0

    #LOCKING_ANDX
    def build_locking_andx(self, cmd, fid, locktype,oplocklevel,listofranges):
        nooflocks = len(listofranges)/2
        datas = ''
        lockcount = 0
        unlockcount = 0
        oplocklevelvalue = 0

        if ( locktype == LOCKING_ANDX_LOCK or
             locktype == LOCKING_ANDX_LARGE_FILE_LOCK):
            lockcount = nooflocks
        else:
            unlockcount = nooflocks
        # Exclusive lock
        if ((locktype==LOCKING_ANDX_UNLOCK or locktype==LOCKING_ANDX_LOCK)
             and oplocklevel):
            locktypevalue = 0x00
        elif ( locktype == LOCKING_ANDX_CHANGE_LOCKTYPE):
            locktypevalue = 0x04
        elif (locktype == LOCKING_ANDX_CANCEL_LOCK):
            locktypevalue = 0x08
        elif (locktype == LOCKING_ANDX_LARGE_FILE_UNLOCK or
              locktype == LOCKING_ANDX_LARGE_FILE_LOCK):
            locktypevalue = 0x10
        elif (locktype == LOCKING_ANDX_OPLOCK_RELEASE):
            locktypevalue = 0x02
        else: #shared mode lock
            locktypevalue = 0x01

        if (locktype == LOCKING_ANDX_LOCK or locktype==LOCKING_ANDX_UNLOCK or
            locktype == LOCKING_ANDX_CHANGE_LOCKTYPE):
            while ( nooflocks ):
                offset = eval(listofranges[0])
                count = eval(listofranges[1])
                datas += struct.pack('<HLL', self.pid, offset, count)
                listofranges = listofranges[2:]
                nooflocks -= 1

        if ( locktype == LOCKING_ANDX_LARGE_FILE_LOCK or
             locktype == LOCKING_ANDX_LARGE_FILE_UNLOCK ):
            while( nooflocks ):
                offset = eval(listofranges[0])
                if ( offset > (1<<32)):
                    offset_high = offset << 32
                    offset_low = (offset - ( 1 << 32))
                count = eval(listofranges[1])
                if ( count > (1<<32)):
                    count_high = count << 32
                    count_low = ( count - ( 1 << 32 ))
                datas += struct.pack('<HHLLLL', self.pid, 0, offset_high,
                                     offset_low, count_high, count_low)
                listofranges = listofranges[2:]
                nooflocks -= 1

        if ( locktype == LOCKING_ANDX_OPLOCK_RELEASE):
            datas = ''
            if (self.capabilities_flags & CAP_LEVEL_II_OPLOCKS):
                oplocklevelvalue = oplocklevel
                locktypevalue = locktypevalue | 1
            else:
                oplocklevelvalue = oplocklevel
                locktypevalue = locktypevalue | 1

        params = struct.pack('<ccHHBBLHH','\xff','0', 0, fid, locktypevalue,
                        oplocklevelvalue, self.lockandxtimeout, unlockcount,
                        lockcount)

        self.send_smb_packet(SMB_LOCKING_ANDX, param=params, data=datas)
        self.fileoperation = 1


    def cmd_locking_andx_request(self, cmd, args):
        oplock = 0
        while(self.client_state < CONNECTED_TO_SHARE or self.fileoperation):
            time.sleep(1)
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    args)
        if ( len(args) < 1):
            print('Missing arguments for lockandx command')

        status, lockreq = g_getlockingandx_from_string(args[0])
        if ( status == 0):
            print 'Unknown lockingandx locktype'
        if ( len(args[2:]) % 2):
            print 'Every lock/unlock should have startoffset and count \
                    parameters'
        (status, fid, eof, alloc_size,
         filetype)=self.fid_db.get_fileinfo_on_filename(args[1])
        if ( status == 0):
            print 'Unable to retireve information for file %s' %(args[1])

        self.build_locking_andx(SMB_LOCKING_ANDX,fid,lockreq,oplock,args[2:])

    def cmd_lock_unlock_andx(self, flags1, flags2, tid, uid, mid, params,
                         data,errClass, errCode):
        print 'TODO: Update the lock database for the file'
        self.fileoperation = 0

    def cmd_locking_andx(self, flags1, flags2, tid, uid,
                         mid, params, data,errClass, errCode):
        if ( len(params) == 4 ):
            self.fileoperation = 0
            return
        (andx, _, andxoff, fid, locktype, oplocklevel, timeout,
         unlockcnt,lockcnt) = struct.unpack('<BBHHBBLHH', params)

        (status,oplock) = self.fid_db.get_createflags_from_fid(fid)
        if ( status == 0):
            print 'FID not found in the FID table'
            return

        if ( locktype == LOCKING_ANDX_OPLOCK_RELEASE and
             (oplocklevel == 0x01 )):
            self.fileoperation = 0
            print 'Oplock break to shared received'
            if ( self.write_on_oplock_break):
                (status, eof) = self.fid_db.get_eof_from_fid(fid)
                if ( status ):
                    self.write_andx_request(SMB_WRITE_ANDX, fid, eof,
                            1024, ('A' * 1024))
                breakcmd = LOCKING_ANDX_SHARED_LOCK
            time.sleep(2)

        elif ( locktype == LOCKING_ANDX_OPLOCK_RELEASE and oplocklevel == 0):
            print 'Oplock break to none received'
            self.fileoperation = 0
            breakcmd = LOCKING_ANDX_SHARED_LOCK
            #TODO: Do we close the file and repoen it here
        time.sleep(2)
        print 'Sending oplock break response for FID = %d \
                with oplock =  %d'%(fid,oplocklevel)
        self.build_locking_andx(SMB_LOCKING_ANDX,fid,
                            LOCKING_ANDX_OPLOCK_RELEASE, oplocklevel|1,[])

        status = self.fid_db.set_createflags_from_fid(fid, oplocklevel)
        if ( status == 0 ):
            print 'New oplock level was not set to the FID table'
            return

        elif ( locktype == 0 or locktype == 1):
            print 'Lock or unlock the byte ranges'
            #self.parse_lock_andx(locktype, fid, lockcnt, unlockcnt, data[2:])
            #TODO - Update the locking table with the offset of its success
        self.testparser.readstop = 0
        self.fileoperation = 0

    def cmd_not_implemented(self, params, data):
        (self.errorclass,
         self.errorcode) = get_expected_error_value(self.capabilities_flags,
                                                    data)
        print 'Not implemented, not used in latest clients'