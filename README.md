# CertificateStealer
This is school Project - learning purpose only !

TIMELINE:
------
The sooner the better ! <br>
I expect a lot of glitches and errors in the process <br>

TO DO:
------
- Cut audio record of project specifications to just this project.      ✅
- Make UML diagrams of program (UseCase diagram, Class diagram).        ❌
- Do research about certificates (storing, extracting, types,...).      ❌
- Make first testing version of program extracting certificates.        ❌
- Debug the first version.                                              ❌
- Rebuild program, upgrade version.                                     ❌
- Hide code (deobfuscate code).                                         ❌
- Try detecting with different antiviruses.                             ❌
- Wrap the code to some application (make it background process).       ❌
- Final tests.                                                          ❌
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
Dont use Python (just Mimikatz is good), it can be used but just for calling powershell functions. So instead of python use POWERSHELL ?

Personal certificates are stored in `dir cert:\currentuser\my` , you can list them and then export.