package model;

import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
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

        //funciones de zip y unzip-------------------funciones de zip y unzip-------------------funciones de zip y unzip-------------------

        /*
		ArrayList<String> paths= new ArrayList<>();
		paths.add("src/test/resources/brayan.txt");
		paths.add("src/test/resources/david.txt");

		zzip(paths,"data");
        */

        //unzzip("data.encr");





        //funciones de encriptado--------------------funciones de encriptado--------------------funciones de encriptado--------------------
		/*
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
			System.out.println("ingrese la contrasena");
			password=scan.next();
			System.out.println("ingrese la ruta del archivo");
			String path=scan.next();
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,"12345");
			File inputFile = Paths.get("src/test/resources/david.txt").toFile();
			File encryptedFile = new File(inputFile.getName()+".encrypted");
			EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
		}else if(valueToChose==2){
			System.out.println("ingrese la contrasena");
			password=scan.next();
			System.out.println("ingrese la ruta del archivo");
			String path=scan.next();
			SecretKey key = EncriptadorAES.getKeyFromPassword(password,"12345");
			File encryptedFile = Paths.get("src/test/resources/david.encrypted").toFile();
			File decryptedFile = new File("document.decrypted");
			//EncriptadorAES.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);
		}else{
			System.out.println("ingrese un valor valido");
		}

		 */

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
