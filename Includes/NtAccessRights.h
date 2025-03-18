#pragma once

#ifndef _NTACCESSRIGHTS_
#define _NTACCESSRIGHTS_

#include "NtCommonDefs.h"


extern "C" {

    typedef DWORD ACCESS_MASK;

    // File related
#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                    FILE_READ_DATA           |\
                                    FILE_READ_ATTRIBUTES     |\
                                    FILE_READ_EA             |\
                                    SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                    FILE_WRITE_DATA          |\
                                    FILE_WRITE_ATTRIBUTES    |\
                                    FILE_WRITE_EA            |\
                                    FILE_APPEND_DATA         |\
                                    SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                    FILE_READ_ATTRIBUTES     |\
                                    FILE_EXECUTE             |\
                                    SYNCHRONIZE)
}

#endif