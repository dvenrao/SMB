class smb2Constants:
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
    
    # SMB2 Oplock Codes
    SMB2_OPLOCK_LEVEL_NONE = 0x00
    SMB2_OPLOCK_LEVEL_II = 0x01
    SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08
    SMB2_OPLOCK_LEVEL_BATCH = 0x09
    SMB2_OPLOCK_LEVEL_LEASE = 0xFF
    
    # SMB2 ImpersonationLevel
    SMB2_Anonymous = 0x00000000
    SMB2_Identification = 0x00000001
    SMB2_Impersonation = 0x00000002
    SMB2_Delegate = 0x00000003
    
    # SMB2 File operation cmds
    #shared access
    SMB2_FILE_SHARE_READ         = 0x00000001
    SMB2_FILE_SHARE_WRITE        = 0x00000002
    SMB2_FILE_SHARE_DELETE       = 0x00000004
    #Directory Access mask
    SMB2_FILE_LIST_DIRECTORY     = 0x00000001
    SMB2_FILE_ADD_FILE           = 0x00000002
    SMB2_FILE_ADD_SUBDIRECTORY   = 0x00000004
    SMB2_FILE_READ_EA            = 0x00000008
    SMB2_FILE_WRITE_EA           = 0x00000010
    SMB2_FILE_TRAVERSE           = 0x00000020
    SMB2_FILE_DELETE_CHILD       = 0x00000040
    SMB2_FILE_READ_ATTRIBUTES    = 0x00000080
    SMB2_FILE_WRITE_ATTRIBUTES   = 0x00000100
    SMB2_DELETE                  = 0x00010000
    SMB2_READ_CONTROL            = 0x00020000
    SMB2_WRITE_DAC               = 0x00040000
    SMB2_WRITE_OWNER             = 0x00080000
    SMB2_SYNCHRONIZE             = 0x00100000
    SMB2_ACCESS_SYSTEM_SECURITY  = 0x01000000
    SMB2_MAXIMUM_ALLOWED         = 0x02000000
    SMB2_GENERIC_ALL             = 0x10000000
    SMB2_GENERIC_EXECUTE         = 0x20000000         
    SMB2_GENERIC_WRITE           = 0x40000000
    SMB2_GENERIC_READ            = 0x80000000
    #File Attributes
    SMB2_FILE_ATTRIBUTE_ARCHIVE             = 0x00000020
    SMB2_FILE_ATTRIBUTE_COMPRESSED          = 0x00000800
    SMB2_FILE_ATTRIBUTE_DIRECTORY           = 0x00000010
    SMB2_FILE_ATTRIBUTE_ENCRYPTED           = 0x00004000
    SMB2_FILE_ATTRIBUTE_HIDDEN              = 0x00000002
    SMB2_FILE_ATTRIBUTE_NORMAL              = 0x00000080
    SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
    SMB2_FILE_ATTRIBUTE_OFFLINE             = 0x00001000
    SMB2_FILE_ATTRIBUTE_READONLY            = 0x00000001
    SMB2_FILE_ATTRIBUTE_REPARSE_POINT       = 0x00000400
    SMB2_FILE_ATTRIBUTE_SPARSE_FILE         = 0x00000200
    SMB2_FILE_ATTRIBUTE_SYSTEM              = 0x00000004
    SMB2_FILE_ATTRIBUTE_TEMPORARY           = 0x00000100
    #Disposition
    SMB2_FILE_SUPERSEDE = 0x00000000
    SMB2_FILE_OPEN = 0x00000001
    SMB2_FILE_CREATE = 0x00000002
    SMB2_FILE_OPEN_IF = 0x00000003
    SMB2_FILE_OVERWRITE = 0x00000004
    SMB2_FILE_OVERWRITE_IF = 0x00000005
    #Options
    SMB2_FILE_DIRECTORY_FILE = 0x00000001
    SMB2_FILE_WRITE_THROUGH = 0x00000002
    SMB2_FILE_SEQUENTIAL_ONLY = 0x00000004
    SMB2_FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
    SMB2_FILE_SYNCHRONOUS_IO_ALERT = 0x00000010
    SMB2_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    SMB2_FILE_NON_DIRECTORY_FILE = 0x00000040
    SMB2_FILE_COMPLETE_IF_OPLOCKED = 0x00000100
    SMB2_FILE_NO_EA_KNOWLEDGE = 0x00000200
    SMB2_FILE_RANDOM_ACCESS = 0x00000800
    SMB2_FILE_DELETE_ON_CLOSE = 0x00001000
    SMB2_FILE_OPEN_BY_FILE_ID = 0x00002000
    SMB2_FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
    SMB2_FILE_NO_COMPRESSION = 0x00008000
    SMB2_FILE_RESERVE_OPFILTER = 0x00100000
    SMB2_FILE_OPEN_REPARSE_POINT = 0x00200000
    SMB2_FILE_OPEN_NO_RECALL = 0x00400000
    SMB2_FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
    
    
    #QUERY_INFO Request InfoType 
    SMB2_0_INFO_FILE        = 0x01
    SMB2_0_INFO_FILESYSTEM  = 0x02
    SMB2_0_INFO_SECURITY    = 0x03
    SMB2_0_INFO_QUOTA       = 0x04
    
    #QUERY_INFO Request AdditionalInformation  Security
    OWNER_SECURITY_INFORMATION  = 0x00000001
    GROUP_SECURITY_INFORMATION  = 0x00000002
    DACL_SECURITY_INFORMATION   = 0x00000004
    SACL_SECURITY_INFORMATION   = 0x00000008
    LABEL_SECURITY_INFORMATION  = 0x00000010
    
    #QUERY_INFO Request Flags
    SL_RESTART_SCAN  = 0x00000001
    SL_RETURN_SINGLE_ENTRY  = 0x00000002
    SL_INDEX_SPECIFIED   = 0x00000004
    
    #CHANGE_NOTIFY Request CompletionFilter 
    FILE_NOTIFY_CHANGE_FILE_NAME     = 0x00000001
    FILE_NOTIFY_CHANGE_DIR_NAME      = 0x00000002
    FILE_NOTIFY_CHANGE_ATTRIBUTES    = 0x00000004
    FILE_NOTIFY_CHANGE_SIZE          = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE    = 0x00000010
    FILE_NOTIFY_CHANGE_LAST_ACCESS   = 0x00000020
    FILE_NOTIFY_CHANGE_CREATION      = 0x00000040
    FILE_NOTIFY_CHANGE_EA            = 0x00000080
    FILE_NOTIFY_CHANGE_SECURITY      = 0x00000100
    FILE_NOTIFY_CHANGE_STREAM_NAME   = 0x00000200
    FILE_NOTIFY_CHANGE_STREAM_SIZE   = 0x00000400
    FILE_NOTIFY_CHANGE_STREAM_WRITE  = 0x00000800
    
    #LOCK Request Flags  
    SMB2_LOCKFLAG_SHARED_LOCK     = 0x00000001
    SMB2_LOCKFLAG_EXCLUSIVE_LOCK  = 0x00000002
    SMB2_LOCKFLAG_UNLOCK          = 0x00000004
    SMB2_LOCKFLAG_FAIL_IMMEDIATELY= 0x00000010
    
    
    #IOCTL Request CtlCode  
    FSCTL_DFS_GET_REFERRALS        = 0x00060194
    FSCTL_PIPE_PEEK                = 0x0011400C
    FSCTL_PIPE_WAIT                = 0x00110018
    FSCTL_PIPE_TRANSCEIVE          = 0x0011C017
    FSCTL_SRV_COPYCHUNK            = 0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS  = 0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY   = 0x00140078
    FSCTL_SRV_READ_HASH            = 0x001441bb
    FSCTL_SRV_COPYCHUNK_WRITE      = 0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY   = 0x001401D4
    

    #Set Info Request [MS-FSCC] if SMB2_0_INFO_FILESYSTEM
    FileFsControlInformation       = 6
    FileFsObjectIdInformation      = 8
    
    #Get Info Request [MS-FSCC] if SMB2_0_INFO_FILE 
    FileAccessInformation                =  8
    FileAlignmentInformation             =  17
    FileAllInformation                   =  18
    FileAllocationInformation            =  19
    FileAlternateNameInformation         =  21
    FileAttributeTagInformation          =  35
    FileBasicInformation                 =  4
    FileBothDirectoryInformation         =  3
    FileCompressionInformation           =  28
    FileDirectoryInformation             =  1
    FileDispositionInformation           =  13
    FileEaInformation                    =  7
    FileEndOfFileInformation             =  20
    FileFullDirectoryInformation         =  2
    FileFullEaInformation                =  15
    FileHardLinkInformation              =  46
    FileIdBothDirectoryInformation       =  37
    FileIdFullDirectoryInformation       =  38
    FileIdGlobalTxDirectoryInformation   =  50
    FileInternalInformation              =  6
    FileLinkInformation                  =  11
    FileMailslotQueryInformation         =  26
    FileMailslotSetInformation           =  27
    FileModeInformation                  =  16
    FileMoveClusterInformation           =  31
    FileNameInformation                  =  9
    FileNamesInformation                 =  12
    FileNetworkOpenInformation           =  34
    FileNormalizedNameInformation        =  48
    FileObjectIdInformation              =  29
    FilePipeInformation                  =  23
    FilePipeLocalInformation             =  24
    FilePipeRemoteInformation            =  25
    FilePositionInformation              =  14
    FileQuotaInformation                 =  32
    FileRenameInformation                =  10
    FileReparsePointInformation          =  33
    FileSfioReserveInformation           =  44
    FileSfioVolumeInformation            =  45
    FileShortNameInformation             =  40
    FileStandardInformation              =  5
    FileStandardLinkInformation          =  54
    FileStreamInformation                =  22
    FileTrackingInformation              =  36
    FileValidDataLengthInformation       =  39
    

# Get Info Request [MS-FSCC] if SMB2_0_INFO_FILESYSTEM
    FileFsVolumeInformation             =  1 
    FileFsLabelInformation              =  2   
    FileFsSizeInformation               =  3
    FileFsDeviceInformation             =  4
    FileFsAttributeInformation          =  5
    FileFsControlInformation            =  6
    FileFsFullSizeInformation           =  7
    FileFsObjectIdInformation           =  8
    FileFsDriverPathInformation         =  9
    FileFsVolumeFlagsInformation        =  10
    
    
    
    