#define _DEFAULT_SOURCE

#include <stdio.h>      // Input/Output
#include <stdlib.h>     // Standard Library
#include <string.h> 
#include <strings.h>    // String library
#include <unistd.h>     // Unix Standard
#include <sys/stat.h>   // Linux sys libs
#include <sys/types.h>
#include <fcntl.h>      // Linux File Control API
#include <dirent.h>     // Linux Directory API
#include <errno.h>      // Error lib

typedef unsigned int uint;

class ProcessManager
{
private:
    char ProcessNameString[1024];
    long ProcessID = 0;
    int ProcessHandle = 0;

    long FindBaseAddress(const char *module = NULL);

public:
    unsigned long TargetBaseAddress = 0;
    
    ProcessManager(const char *szProcessName, const char *module = NULL);
    ~ProcessManager();

    bool SignaturePayload(const char *signature, char *payload, const int siglen, const int paylen, const int bsize, uint sigoffset = 0);

    bool WriteProcessMemory(unsigned long address, void *buffer, uint size);

    bool ReadProcessMemory(unsigned long address, void *buffer, uint size);
};
