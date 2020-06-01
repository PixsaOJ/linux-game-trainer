#include "ProcessManager.h"

// Find base address of memory to start searching for signature
//
// Default base address will be the first executable region

long ProcessManager::FindBaseAddress(const char *module)
{
    int fd = 0;
    char FileLocation[1024]; // File location to read memory modules
    char BaseAddress[1024];
    char *ptr = NULL;

    sprintf(FileLocation, "/proc/%lu/maps", ProcessID);

    // Open file
    if ((fd = open(FileLocation, O_RDONLY)) < 0)
    {
        fprintf(stderr, "(ERROR) ProcessManager: Failed to find process base address\n");
        return false;
    }

    // Create buffer for file
    char *FileBuffer = (char *)malloc(100000);
    if (FileBuffer == NULL)
    {
        fprintf(stderr, "(ERROR) ProcessManager: Failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }

    memset(FileBuffer, 0, 100000);
    memset(BaseAddress, 0, 1024);

    // Read file into buffer
    for (int i = 0; read(fd, FileBuffer + i, 1) > 0; i++)
        ;

    // Close file
    close(fd);

    // Locate Base address
    if (module != NULL)
    {
        if ((ptr = strstr(FileBuffer, module)) == NULL)
        {
            fprintf(stderr, "(ERROR) ProcessManager: Failed to locate base memory address; NON\n");
            return false;
        }
    }
    else
    {
        if ((ptr = strstr(FileBuffer, "r-xp")) == NULL)
        {
            fprintf(stderr, "(ERROR) ProcessManager: Failed to locate base memory address\n");
            return false;
        }
    }

    // Copy address
    while (*ptr != '\n' && ptr >= FileBuffer)
    {
        ptr--;
    }
    ptr++;

    for (int i = 0; *ptr != '-'; i++)
    {
        BaseAddress[i] = *ptr;
        ptr++;
    }

    // Copy over address to public
    return strtol(BaseAddress, NULL, 16);
}

// Function will automatically search for signature and write payload

bool ProcessManager::SignaturePayload(const char *signature, char *payload, const int siglen, const int paylen, const int bsize, uint sigoffset)
{
    // Create buffer to hold read memory
    char *buf = (char *)malloc(siglen * bsize);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to create buffer!\n");
        exit(EXIT_FAILURE);
    }

    // Buffer read/analyse for signature then write payload to target location
    for (int i = 0; ReadProcessMemory(TargetBaseAddress + i, buf, siglen * bsize) == true; i += (siglen * bsize))
    {
        for (int j = 0; j < ((siglen * bsize) - (siglen - 1)); j++)
        {
            if (memcmp(buf + j, signature, siglen) == 0)
            {
                printf("Signature Found!\n");

                if (payload != NULL)
                    WriteProcessMemory((TargetBaseAddress + i + j) + sigoffset, payload, paylen);

                goto END;
            }
        }
    }

END:

    free(buf);

    return true;
}

// Function will write to target memory

bool ProcessManager::WriteProcessMemory(unsigned long address, void *buffer, uint size)
{
    lseek(ProcessHandle, address, SEEK_SET);

    if (!write(ProcessHandle, buffer, size))
    {
        fprintf(stderr, "(ERROR) ProcessManager: Failed to write to target process memory! : %s\n", strerror(errno));
        return false;
    }

    lseek(ProcessHandle, 0, SEEK_SET);

    return true;
}

// Function will read from target memory

bool ProcessManager::ReadProcessMemory(unsigned long address, void *buffer, uint size)
{
    lseek(ProcessHandle, address, SEEK_SET);

    if (!read(ProcessHandle, buffer, size))
    {
        fprintf(stderr, "(ERROR) ProcessManager: Failed to read target process memory!\n");
        return false;
    }

    lseek(ProcessHandle, 0, SEEK_SET);

    return true;
}

// Contructer will automatically attach itself to a process of choice

ProcessManager::ProcessManager(const char *szProcessName, const char *module) {
    // Check string length
    if(strlen(szProcessName) >= 1023) {
        fprintf(stderr, "(ERROR) ProcessManager: Process name is to long...\n");
        exit(EXIT_FAILURE);
    }

    // Copy string to private class buffer
    strcpy(ProcessNameString, szProcessName);

    // Create directory objects
    struct dirent   *DirectoryObject = NULL;
    DIR             *DirectoryHandle = NULL;

    // Open directory
    if((DirectoryHandle = opendir("/proc/")) == NULL) {
        fprintf(stderr, "(ERROR) ProcessManager: Failed to open PROC file system. Are you root?\n");
        exit(EXIT_FAILURE);
    }

    // Search for process
    while((DirectoryObject = readdir(DirectoryHandle)) != NULL) {
        // Check if directory is number(Process ID File)
        if(atoi(DirectoryObject->d_name) != 0) {
            char    FilePath[1024];
            char    *FileBuffer = NULL;
            __off_t FileLength  = 0;
            int     fd          = 0;

            sprintf(FilePath, "/proc/%s/status", DirectoryObject->d_name);  // Create new file path to read
            
            // Open status file
            if((fd = open(FilePath, O_RDONLY)) < 0) {
                fprintf(stderr, "(ERROR) ProcessManager: Failed to open PROC status file. Are you root?\n");
                exit(EXIT_FAILURE);
            }

            // Get file length
            FileLength = 128;

            // Create file buffer
            if((FileBuffer = (char *)malloc(FileLength)) == NULL) {
                fprintf(stderr, "(ERROR) ProcessManager: malloc()\n");
                exit(EXIT_FAILURE);
            }
            memset(FileBuffer, 0, FileLength);

            // Copy file to buffer
            if(read(fd, FileBuffer, FileLength - 1) < 0) {
                fprintf(stderr, "(ERROR) ProcessManager: Failed to read PROC status file. Are you root? : %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }

            // Close status file
            close(fd);

            // Check if process is correct
            if(strstr(FileBuffer, ProcessNameString) != NULL) {
                printf("Process %s:%s found!\n", ProcessNameString, DirectoryObject->d_name);
                ProcessID = atol(DirectoryObject->d_name);

                // Unlock target memory
                //ptrace(PTRACE_ATTACH, ProcessID, NULL, NULL);

                // Create buffer to open target memory
                char TargetMemoryLocation[1024];
                sprintf(TargetMemoryLocation, "/proc/%s/mem", DirectoryObject->d_name);

                // Get the program base address
                TargetBaseAddress = FindBaseAddress(module);

                // Open target process memory
                if((ProcessHandle = open(TargetMemoryLocation, O_RDWR)) < 0) {
                    fprintf(stderr, "(ERROR) ProcessManager: Failed to ropen target process memory. Are you root? : %s\n", strerror(errno));
                    exit(EXIT_FAILURE);          
                }

                free(FileBuffer);
                break;
            }

            // Free file buffer
            free(FileBuffer);
        }
    }

    // Close directory
    closedir(DirectoryHandle);
}

// Deconstructor will close handle on target process

ProcessManager::~ProcessManager() {
    if(ProcessHandle != 0) {
        //ptrace(PTRACE_DETACH, ProcessID, NULL, NULL);
        close(ProcessHandle);
    }
}