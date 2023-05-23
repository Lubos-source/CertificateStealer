<?php

$target_dir = "uploads/";
$uploadOk = 1;
$target_path = $target_dir . basename( $_FILES['fileToUpload']['name']);

if(move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $target_path)) {
echo "The file ".  basename( $_FILES['fileToUpload']['name']). " has been uploaded";
} else{
echo "There was an error uploading the file, please try again!";
}

?>