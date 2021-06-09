package model;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.zip.*;
import java.util.zip.ZipOutputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

public class EncriptadorAES {

    /**
     * Este metodo se encarga de generar un objeto de tipo SecretKey a partir de la contraseña y la sal
     * @param password contraseña para encriptar el archivo
     * @param salt sal aleatoria para el proceso de encriptado
     * @return Objeto de tipo SecretKey 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    /**
     * Este método se encarga de generar la sal aleatoria al realizar el proceso de encriptado
     * @return sal aleatoria de tipo Integer
     */
    public static int generateSalt(){
        Random random=new Random();
        int num =random.nextInt(90000) + 10000;
        return num;
    }

    /**
     * Este método se encarga de leer el contenido de un archivo
     * @param path Ruta del archivo
     * @return Contenido del archivo 
     * @throws IOException
     */
    public static String readFile(String path) throws IOException {
        String cadena;
        String result="";
        FileReader f = new FileReader(path);
        BufferedReader b = new BufferedReader(f);
        while((cadena = b.readLine())!=null) {
            result+=cadena;
        }
        b.close();
        return result;
    }

    /**
     * Este método se encarga de crear un nuevo archivo
     * @param name Nombre del nuevo arhivo
     * @param topic Contenido del archivo a crear
     */
    public static void createFile(String name, String topic){
        try {
            String ruta = "src/test/resources/"+name;
            File file = new File(ruta);
            // Si el archivo no existe es creado
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file);
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(topic);
            bw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Este método se encarga de generar un objeto de tipo IvParameterSpec, que se refiere a vector de inicialización de 16 bits
     * necesario para el proceso de encriptación
     * @return Vector de inicialización aleatorio de 16 bits 
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Este método encripta un archivo seleccionado 
     * @param algorithm algoritmo de encriptación a definir
     * @param key Objeto de tipo SecretKey generado a partir de una contraseña y sal aleatoria
     * @param iv vector de inicialización aleatorio 
     * @param inputFile Archivo a encriptar
     * @param outputFile Archivo final encriptado 
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    /**
     * Este método genera la función hash SHA-1 en un archivo
     * @param file Archivo al cual se le firmará el SHA-1
     * @return Archivo resultante en formato byte
     * @throws Exception
     */
    public static byte[] createSha1(File file) throws Exception  {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        InputStream fis = new FileInputStream(file);
        int n = 0;
        byte[] buffer = new byte[8192];
        while (n != -1) {
            n = fis.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        return digest.digest();
    }

    /**
     * Este método comprime los archivos correspondientes al iv y la sal
     * @param filesSrc Arreglo de tipo String con las rutas de los archivos a comprimir
     * @param fileName Nombre del archivo resultante del proceso de compresión 
     * @throws IOException
     */
    public static void zzip(List<String> filesSrc,String fileName) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName+".encr");
        ZipOutputStream zipOut = new ZipOutputStream(fos);
        for (String srcFile : filesSrc) {
            File fileToZip = new File(srcFile);
            FileInputStream fis = new FileInputStream(fileToZip);
            ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
            zipOut.putNextEntry(zipEntry);

            byte[] bytes = new byte[1024];
            int length;
            while((length = fis.read(bytes)) >= 0) {
                zipOut.write(bytes, 0, length);
            }
            fis.close();
        }
        zipOut.close();
        fos.close();
    }


    /**
     * Este método descomprime el archivo comprimido con el método zzip
     * @param SrcFileZip
     * @return
     * @throws IOException
     */
    public static String unzzip(String SrcFileZip) throws IOException {
        String encripted="";
        final byte[] buffer = new byte[1024];
        final ZipInputStream zis = new ZipInputStream(new FileInputStream(SrcFileZip));
        ZipEntry zipEntry = zis.getNextEntry();
        while (zipEntry != null) {
            if (zipEntry.getName().endsWith(".encrypted")){
                encripted=zipEntry.getName();
            }
            final File newFile = new File(zipEntry.getName());
            final FileOutputStream fos = new FileOutputStream(newFile);
            int len;

            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();

            zipEntry = zis.getNextEntry();
        }
        zis.closeEntry();
        zis.close();
        return encripted;
    }

    /**
     * Este método compara el valor SHA-1 entre dos archivos
     * @param sha11 ruta del archivo con la función hash
     * @param sha12 ruta del archivo el cual tiene firmado la función hash
     * @return Dato de tipo booleano en donde es verdarero si hay igualdad, y falso en caso contrario
     * @throws IOException
     */
    public static Boolean comparateSHA1(String sha11,String sha12) throws IOException {

        String realSha11=readFile(sha11);
        String realSha12=readFile(sha12);

        return realSha11.equals(realSha12);

    }


    /**
     * Este método desencripta un archivo seleccionado 
     * @param algorithm algoritmo de encriptación a definir
     * @param key Objeto de tipo SecretKey generado a partir de una contraseña y sal aleatoria
     * @param iv vector de inicialización aleatorio 
     * @param encryptedFile Archivo a encriptar 
     * @param decryptedFile Nuevo Archivo con la ruta en el cual se guardará
     * @throws IOException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File encryptedFile,
                                   File decryptedFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);

        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            outputStream.write(output);
        }
        inputStream.close();
        outputStream.close();
    }

    /**
     * Metodo para remover un archivo del proyecto
     * @param path ruta del archivo a eliminar
     */
    public static void deleteFile(String path) {
    	 File file=new File(path);
    	 file.delete();
    }

    public static void main(String[] args) throws Exception {

		String algorithm = "AES/CBC/PKCS5Padding";
		String password="";
		int valueToChose=0;


		Scanner scan= new Scanner(System.in);
		System.out.println("BIENVENID@");
		System.out.println("");
		System.out.println("");
		System.out.println("Que desea realizar? Digite 1 para encriptar, 2 para desencriptar");

		try {
			valueToChose=scan.nextInt();
		}catch (Exception e){
			e.printStackTrace();
		}
		
		if(valueToChose==1){
			//Generar IvParameter
			IvParameterSpec ivParameterSpec = EncriptadorAES.generateIv();
            String encoded = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
            createFile("iv.txt",encoded);
            
			System.out.println("Ingrese la contraseña con la cual cifraras el archivo");
			password=scan.next();
			
			System.out.println("Ingrese la ruta del archivo a cifrar");
			String path=scan.next();
			
			//Generar Salt
			int saltnew=generateSalt();
			createFile("salt.txt",saltnew+"");

			//Generar key a partir de password dada
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,saltnew+"");

			//Archivo a encriptar
			File inputFile = Paths.get(path).toFile();
            createFile("realName.txt",inputFile.getName());

            //Generar SHA-1
			String sha164=Base64.getEncoder().encodeToString(createSha1(inputFile));
			createFile("sha.txt",sha164);

			//Encriptar archivo
			File encryptedFile = new File("file.encrypted");
			try{
                EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
                System.out.println("El archivo se ha cifrado correctamente. Puedes verlo en el siguiente path: "+ encryptedFile.getPath());
            }catch (Exception e){
                System.out.println("Ha ocurrido un error al encriptar el archivo" + e.getMessage());
            }

			List<String> rutas= Arrays.asList("src/test/resources/iv.txt","src/test/resources/salt.txt",
					"src/test/resources/sha.txt","file.encrypted","src/test/resources/realName.txt");
	
			zzip(rutas,"file");
            deleteFile("src/test/resources/iv.txt");
            deleteFile("src/test/resources/salt.txt");
            deleteFile("src/test/resources/sha.txt");
            deleteFile("src/test/resources/realName.txt");
            deleteFile("file.encrypted");




		}else if(valueToChose==2){
		    //Recibir valores
			System.out.println("Ingrese la contraseña para descifrar el archivo");
			password=scan.next();
			System.out.println("Ingrese la ruta del archivo a descifrar");
			String path=scan.next();

			//Descomprimir zip que contiene el archivo cifrado y la demas info
			String encripNAme=unzzip(path);

            System.out.println("Descrifrando archivo......\n");
			//Obtener salt
            String salt=readFile("salt.txt");
            System.out.println("Obteniendo Salt...");

            //Obtener IVparameter
            byte[] decoded = Base64.getDecoder().decode(readFile("iv.txt"));
            IvParameterSpec ivspec= new IvParameterSpec(decoded);
            System.out.println("Obteniendo IvParameter...");

            //Obtener secretKey
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,salt);
            System.out.println("Obteniendo SecretKey...");

            //Obtener archivo cifrado
			File encryptedFile = Paths.get(encripNAme).toFile();

			//Obtener nombre real del archivo
			String nameReal=readFile("realName.txt");

			//Archivo descifrado
			File decryptedFile = new File(nameReal);

            try{
			    EncriptadorAES.decryptFile(algorithm, key, ivspec, encryptedFile, decryptedFile);
            }catch (BadPaddingException e) {
                System.out.println("La clave para descifrar el archivo es incorrecta: " + e.getMessage());
            }

            System.out.println("Comparando SHA-1 de los archivos...\n");
            String sha164=Base64.getEncoder().encodeToString(createSha1(decryptedFile));
            createFile("shaFinal.txt",sha164);
            if (comparateSHA1("sha.txt","src/test/resources/shaFinal.txt")){
                System.out.println("El SHA-1 de los 2 archivos coincide. Descifrado correcto");
                System.out.println("Puedes ver el archivo descifrado en la ruta: "+decryptedFile.getPath());

            }else{
                System.out.println("El SHA-1 de los 2 archivos no coincide. Descifrado incorrecto");
            }

            deleteFile("iv.txt");
            deleteFile("salt.txt");
            deleteFile("sha.txt");
            deleteFile("file.encrypted");
            deleteFile("realName.txt");
            deleteFile("src/test/resources/shaFinal.txt");

		}else{
			System.out.println("Por favor ingrese un valor valido (1,2)");
		}


    }

}
