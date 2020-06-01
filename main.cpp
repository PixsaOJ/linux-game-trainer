/*/
 * ## Visit YT: Guided Hacking
 * Project: Proof of Concept
 * Goal:    Infinite Ammo
 * Target:  Assault Cube
 * File:    beef.cpp
 * 
 * g++ beef.cpp ProcessManager.cpp -Wall -o NAME
/*/

#include "ProcessManager.h"

int main(const int argc, const char *argv[]) {
    const char szSignature[] = "\x48\x8b\x45\x28\x83\x28\x01\x48";
    char szOpCode[] = "\x90\x90\x90";

    printf("ac_client");
    // Code starts executing here...
    ProcessManager procManager("ac_client");

    // Launch Payload
    procManager.SignaturePayload(szSignature, szOpCode, strlen(szSignature), strlen(szOpCode), 64, 4);


    exit(EXIT_SUCCESS); // Terminate process
}
