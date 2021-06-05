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

public class EncriptadorAES {

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    public static int generateSalt(){
        Random random=new Random();
        int num =random.nextInt(90000) + 10000;
        return num;
    }

    public static String readFile(String path) throws IOException {
        String cadena;
        String result="";
        FileReader f = new FileReader(path);
        BufferedReader b = new BufferedReader(f);
        while((cadena = b.readLine())!=null) {
            System.out.println(cadena);
            result+=cadena;
        }
        b.close();
        return result;
    }

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

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

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

    public byte[] createSha1(File file) throws Exception  {
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

    public static void zzip(ArrayList<String> filesSrc,String fileName) throws IOException {
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
    public static void unzzip(String SrcFileZip) throws IOException {
        final byte[] buffer = new byte[1024];
        final ZipInputStream zis = new ZipInputStream(new FileInputStream(SrcFileZip));
        ZipEntry zipEntry = zis.getNextEntry();
        while (zipEntry != null) {
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
    }






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

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {




        //funciones de escritura y hash sha1-----------funciones de escritura y hash sha1-----------funciones de escritura y hash sha1-----------

        /*
        createFile("archivoTest.txt",generateSalt()+"");
        */

        //funciones de zip y unzip-------------------funciones de zip y unzip-------------------funciones de zip y unzip-------------------

        /*
		ArrayList<String> paths= new ArrayList<>();
		paths.add("src/test/resources/brayan.txt");
		paths.add("src/test/resources/david.txt");

		zzip(paths,"data");
        */

        //unzzip("data.encr");



        //funciones de encriptado y menu--------------------funciones de encriptado y menu--------------------funciones de encriptado y menu--------------------


		String algorithm = "AES/CBC/PKCS5Padding";
		String password="";
		int valueToChose=0;

		Scanner scan= new Scanner(System.in);
		System.out.println("Bienvenido");
		System.out.println("");
		System.out.println("");
		System.out.println("Que desea realizar? digite 1 para encriptar, 2 para desencriptar");

		try {
			valueToChose=scan.nextInt();
		}catch (Exception e){
			e.printStackTrace();
		}

		if(valueToChose==1){
			IvParameterSpec ivParameterSpec = EncriptadorAES.generateIv();
            String encoded = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
            System.out.println(encoded);
			createFile("iv.txt",encoded);
			System.out.println("ingrese la contrasena");
			password=scan.next();
			System.out.println("ingrese la ruta del archivo");
			String path=scan.next();
			int saltnew=generateSalt();
			createFile("salt.txt",saltnew+"");
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,saltnew+"");
			File inputFile = Paths.get(path).toFile();
			File encryptedFile = new File(inputFile.getName()+".encrypted");
			EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
		}else if(valueToChose==2){
			System.out.println("ingrese la contrasena");
			password=scan.next();
			System.out.println("ingrese la ruta del archivo");
			String path=scan.next();
            String salt=readFile("src/test/resources/salt.txt");
            byte[] decoded = Base64.getDecoder().decode(readFile("src/test/resources/iv.txt"));
            //byte[] data=readFile("src/test/resources/iv.txt").getBytes(StandardCharsets.UTF_8);
            System.out.println(decoded);
            IvParameterSpec ivspec= new IvParameterSpec(decoded);
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,salt);
			File encryptedFile = Paths.get(path).toFile();
			File decryptedFile = new File("document.decrypted");
			EncriptadorAES.decryptFile(algorithm, key, ivspec, encryptedFile, decryptedFile);
		}else{
			System.out.println("ingrese un valor valido");
		}



		/*

		SecretKey key = EncriptadorAES.getKeyFromPassword("huertasesbimba","12345");

        //como voy a desencriptar sin tener el mismo IV :(
        IvParameterSpec ivParameterSpec = EncriptadorAES.generateIv();
        File inputFile = Paths.get("src/test/resources/david.txt")
            .toFile();
        File encryptedFile = new File(inputFile.getName()+".encrypted");
        File decryptedFile = new File("document.decrypted");


        SecretKey key2 = EncriptadorAES.getKeyFromPassword("douglassesbimba","12345");
        // when
        EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        EncriptadorAES.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);
		*/
    }

}
