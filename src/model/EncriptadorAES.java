package model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

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
		
		
		SecretKey key = EncriptadorAES.getKeyFromPassword("huertasesbimba","12345");
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = EncriptadorAES.generateIv();
        File inputFile = Paths.get("src/test/resources/david.txt")
            .toFile();
        File encryptedFile = new File(inputFile.getName()+".encrypted");
        File decryptedFile = new File("document.decrypted");

        
        SecretKey key2 = EncriptadorAES.getKeyFromPassword("douglassesbimba","12345");
        // when
        EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        EncriptadorAES.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);

	}

}
