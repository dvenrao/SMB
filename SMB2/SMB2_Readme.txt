'negotiate' ---  SMB2_NEGOTIATE
    - The first command to start the client negotiation.  This command can be called  
      with no argument (populated from the smbsetup.cfg)
      and initiates a connection with the CIFS server/proxy 

      Usage:  ntstatus = negotiate 
      
      If it is successfull it returns 0 otherwise it returns ntstatus code.        
Note:- For every command ntstatus is like above.


'session_setup' --- SMB2_SESSION_SETUP
    - This command sends SMB2_SESSION_SETUP request and the client can
      reads username and password from the configuration file (smbsetup.cfg). 
      This command does not require any arguments.

      Usage:  ntstatus,sid = session_setup
      
      Returns session-id.


'tree_connect' ---  SMB2_TREE_CONNECT
    - This command is used to connect to a share on the CIFS server. The share 
      name can be passed as an argument to this command.If you doesnot pass
      sharename it will takes from configuration file.

      Usage: ntstatus,tid = tree_connect (default sharename from smbsetup.cnf will be used)
             ntstatus,tid = tree_connect [share-name]
              
      Returns tree-id.

'tree_disconnect' --- SMB2_TREE_DISCONNECT
    - This command is used to disconnect from the share to which the client has 
      connected. The tid can be passed as an argument to this command. 

      Usage: ntstatus = tree_disconnect [tid]
             

'logoff' --- SMB2_LOGOFF
    - Close the client session. This command is used at the end of complete
      client session with the server ,takes sid as argument.

      Usage: ntstatus = logoff [sid]



'create' --- SMB2_CREATE
    - This command opens a existing file or a new file based on the parameters
      passed to it. The first argument is tid than the filename.  
      The arguments are provided with the value as seen in the 
      SMB2_CREATE packets.  
      The following are the list of arguments:
      a) tid
      b) oplock         [0]
      c) accessmask     [7]
      d) fileattr       [128]
      e) sharemode      [7]
      f) disposition    [1]
      g) createoptions  [2112]
      h) DHNQ 
      i) MXAC timestamp
      j) QFID
      k) DHNC fileId
      l) ALSI allocationsize
      m) TWRP timestamp
      n) SECD

 
      If not arguments follow the filename then the default values will be used.
      The default values are mentioned above from b) to g)along side the name of the
      arguments

      Usage: ntstatus,fileid ,filesize  = nt_create <filename> [file open arguments as mentioned above]

      nt_create testfile.txt
        - Default values will be considered during opening the file.
          nt_create testfile.txt oplock=6 accessmask=7 fileattr=128 sharemode=0
          disposition=1 createoptions=2112



'close' --- SMB2_CLOSE
	  - This command is used to close an already opened file. The arguments 
          to this function are fileId, tid 

          Usage: ntstatus = close tid,fileId 


'read'  --- SMB2_READ
      - This command is used to read either a range of bytes in the opened 
        file or the entire file can be read. The command accepts tid
        fileId and filesize which returned from create command 
        optionally followed by start offset and the number of 
        bytes to be read. Passing only the fileId will read the file in 
        entirety. If the reading of file is more that 32768 bytes,than
        it reads in successive read commands with 32768 bytes are generated 
        in the client until eof is found.

        Usage: ntstatus = read <tid> <fileId> <filesize>
               ntstatus = read <tid> <fileId> <filesize> [start_offset] [no_of_bytes_to_read

'flush'  --- SMB2_FLUSH
      - Genereates a flush message to write the contents to the disk.

        Usage: ntstatus = flush <fileId>
       
'write' --- SMB2_WRITE
      - This command is used to write bytes in opened file at a specified 
        offset of at the end of the file. The command accepts start offset 
        and the write contents.It will takes arguments fileId followed 
        by start offset and data. Passing only the tid, fileId will writes  
        at begining of file the file in entirety. 

        Usage: ntstatus = write <tid> <fileId> 
               ntstatus = write <tid> <fileId> [start_offset] [data]

'Query_info' --- SMB2_Query-Info
      - This command is used to get the information of file. . 

        Usage: ntstatus = query_info <tid> <fileId> --
               The following are the list of arguments:
               a) InfoType=SMB2_0_INFO_FILE,file_information_class
               b) InfoType=SMB2_0_INFO_FILESYSTEM,fs_information_class
               c) InfoType=SMB2_0_INFO_SECURITY,AdditionalInformation
               d) InfoType=SMB2_0_INFO_QUOTA,AdditionalInformation,ReturnSingle=TRUE/FALSE \
                    RestartScan=TRUE/FALSE,SidListLength
            

          Client test script
          ===================
          
          ntstatus = login()
          ntstatus,msgid,sid,tid =  tree_connect(share)     
          ntstatus,fileId, filesize =  create(tid,"newfile.txt","oplock=0","accessmask=7","fileattr=128", \
                                   "sharemode=7","disposition=1", "createoptions=2112")
          ntstatus = read(tid, fileId, filesize, "offset=1", "length=78689")
          ntstatus = write(tid, fileId, "offset=10","data = welcome")
          ntstatus = close(tid ,fileId)
          ntstatus = tree_disconnect(tid)
          ntstatus = logoff()


          Client2 testscript
          ==================
               
          ntstatus = login()
          ntstatus,msgid,sid,tid =  tree_connect("\\\\"+remoteIP+"\\"+share)      
          ntstatus,fileId, filesize =  create(tid,"ram.txt","oplock=0","accessmask=7","fileattr=128", \
                         "sharemode=7","disposition=1", "createoptions=2112","DHNQ","MXAC","QFID")
          ntstatus = write(tid, fileId, "offset=0","data = hello welcome hello welcome hello welcome hello welcome")
          ntstatus = read(tid, fileId, filesize, "offset=1", "length=7")
          ntstatus = read(tid, fileId, filesize)
          ntstatus = write(tid, fileId, "offset=100","data = as;a sa; sa;s;as ;as;a;sa;sa;s;a")
          ntstatus = write(tid, fileId)
          ntstatus = close(tid ,fileId)
          ntstatus = tree_disconnect(tid)
          ntstatus = logoff()
        
   