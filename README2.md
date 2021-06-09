# CipherDes

Este pequeño programa se trata de un cifrador de todo tipo de arhivos, e igualmente con la posibilidad de descifrarlos a partir de una contraseña otorgada por el usuario 
en el proceso de cifrado. Se recibe como entrada el archivo que se desea cifrar y una contraseña. Con la contraseña y un valor aleatorio (sal) se generará 
una clave de 128 bits con la ayuda del algoritmo PBKDF2 y luego cifrará el archivo con la metodología de cifrado AES-CBC junto con un hash SHA-1 específico,
generando un archivo correspondiente al archivo cifrado. Para el proceso descifrado, se recibe el archivo cifrado junto con su respectiva contraseña. Si todo es correcto, se procederá a
comparar el hash del archivo descifrado con el almacenado en el archivo cifrado.

## Al iniciar el programa:

-El programa le dara las opciones de cifrar y descifrar un archivo que se refieren a las entradas numericas 1 y 2, respectivamente. 
-Independiente de la opción que se escoja, es necesario que como entrada se dé la ruta del archivo con el que se llevará a cabo el proceso en concreto y su correspondiente contraseña.
