#!/usr/bin/env python

##
## testparser.py
## Python SMBClient 
## The python smbclient is implemented to aid in unit testing of cifs proxy.  smbclientpy takes test scripts as input and generated requests to the
## server/cifs proxy and verifies the reponse from the server.

import os
import os.path
import sys, string

from smbconstants import *



# State during parsing of test_script
NONE=0
SETUP_INFO=1
TEST_CASE=2

###########################################################################################
#Command line parser to read the test scripts
###########################################################################################

#
# Checks whether the given line is a comment line or not.
#


class TestCodeParser:
    def __init__(self, testfilename):
        self.testfilename = testfilename
        self.testfile_fd = -1
        self.testcasename = ''
        self.description = ''
        self.readstop = 0
        
    def open_test_file(self):
        try:
            self.testfile_fd = open(self.testfilename,'r')
            if self.testfile_fd < 0:
                print "Test script file could not be opened: %s" % self.testfilename
                return 0
            return 1
        except:
            print "%s file not found" %self.testfilename
            return 0

    def close_test_file(self):
        self.testfile_fd.close()
        
    def is_comment_line(self, ln):
        if len(ln) >= 1 and ln[0] == '#':
            return 1
        return 0

    #
    # This expects a stripped line as argument. 
    # If the length of the line is 0, then it is a blank line
    #
    def is_blank_line(self,ln):
        return ((len(ln)== 0) or (len(ln) == 1 and ln[0] == '\n'))


    #
    # This function validates whether the line is a valid spec line.
    # - Comment line or blank line is not a spec line
    # - It also trims the trailing comment on the spec line.
    #
    # Returns 1 if valid and 0 if not.
    # This also returns whether end-of-file has been reached.
    #
    def valid_script_line(self, ln):
        eof = 0
        # if empty line, return valid. this will return End-Of-File
        if ln == '':
            #print "EOF reached"
            eof = 1
            return eof, 0, ln

        if self.is_blank_line(ln):
            #print "This is is a blank line: %s" % ln
            return eof, 0, ln

        # Strip white space on both sides and trim the comment
        ln = string.strip(ln)
        if self.is_comment_line(ln) or self.is_blank_line(ln):
            #print "This line is a comment line or a blank line: %s" % ln
            return eof, 0, ln

        # trim the trailing comment
        ind = string.find(ln, "#")
        if ind > 0:
            ln = ln[:ind]
            # print "This stripping trailing comment: %s" % ln

        return eof, 1, ln


    def get_cmd_num(self, keyword):
        print 'Yet to implement'

    def match_keyword(self, keyword):
        found = 0
        for list in TEST_SCRIPT_KEYWORDS:
            if list[0] == keyword:
                found = 1
                break
        return found            

    def get_cmd_num(self, keyword):
        found = SMB_NONE
        for list in TEST_SCRIPT_KEYWORDS:
            if list[0] == keyword:
                found = list[1]
                break
        return found

    def get_build_cmd_args(self, args):
        return args
        

    def build_cmd_and_args(self, ln):
        # Return the cifs command and its arguments
        eof, valid, ln = self.valid_script_line(ln)
        if (eof == 0 or eof == 1) and valid == 0:
            return 0, SMB_NONE, []
        
        line = string.split(ln)
        ln_len = len(line)
        if ln_len >= 1:
            i = 1
            if self.match_keyword(line[0]):
                if cmp(line[0], 'test:') == 0:
                    self.testcasename = line[1:]
                    return 1, SMB_NONE, []
                elif cmp(line[0], 'description:') == 0:
                    self.description = line[1:]
                    return 1, SMB_NONE, []
                else:    
                    cmd = self.get_cmd_num(line[0])
                    if ( ln_len > 1 ):
                        args_list = self.get_build_cmd_args(line[1:])
                        return 1, cmd, args_list
                    return 1, cmd, []
            else:
                print "Command \"%s\" not found" %line[0] 
                return 0, NONE, []


    def get_next_command_and_args(self, ln):
        return self.build_cmd_and_args(ln)

    #
    # This function parses test script file and generates the SMB request packets
    # for every valid keyword found.
    #
    # Argument for this function is:
    #   filename: filename of the test file.
    #

    def parse_test_script(self):
        if test.open_test_file():
            while 1:
                ln = self.testfile_fd.readline()
                if not ln:
                    break
                self.get_next_command_and_args(ln)                    
            else:
                print "file is empty!!"
                failed = 0

            self.close_test_file()
#################################################################################

#
# Start of the Python SMB client
#
            
           
if __name__ == "__main__":
    test = TestCodeParser(sys.argv[1])
    test.parse_test_script()
                      


        
    
    


