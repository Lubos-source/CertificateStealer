# Script to export certificate from LocalMachine store along with private key - just exportable certificate
$Password = "zkouska"; #password to access certificate after exporting
$ExportPathRoot = "C:\Users\lubos\Documents"
$CertListToExport = Get-ChildItem -Path cert:\LocalMachine\My

foreach($CertToExport in $CertListToExport)
{
    
    $DestCertName=$CertToExport.Subject.ToString().Replace("CN=","");
    #$DestCertName = $DestCertName.Substring(0, $DestCertName.IndexOf(","));

    $CertDestPath = Join-Path -Path $ExportPathRoot -ChildPath "$DestCertName.pfx"

    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

    # Export PFX certificate along with private key
    Export-PfxCertificate -Cert $CertToExport -FilePath $CertDestPath -Password $SecurePassword -Verbose
}

#ERROR: Export-PfxCertificate : Cannot export non-exportable private key.
#get thumbprint of certrificate for next exporting (bcs NonExportable key)
#(Get-ChildItem -Path Cert:\LocalMachine\My -Recurse).Thumbprint
#Export from registry (should have PrivateKey also as NoExportable)
#Export-Clixml
#certutil
