package test;

import org.junit.jupiter.api.Assertions;

import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

import model.EncriptadorAES;

public class EncrypterTest {
	@Test
    void givenFile_whenEncrypt_thenSuccess()
        throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
        BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException {
        // given
        SecretKey key = EncriptadorAES.getKeyFromPassword("huertasesbimba","12345");
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = EncriptadorAES.generateIv();
        File inputFile = Paths.get("src/test/resources/david.txt")
            .toFile();
        File encryptedFile = new File("classpath:baeldung.encrypted");
        File decryptedFile = new File("document.decrypted");

        // when
        EncriptadorAES.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        EncriptadorAES.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);

        // then
       // assertThat(inputFile).hasSameTextualContentAs(decryptedFile);
        encryptedFile.delete();
        decryptedFile.delete();
    }
	
}
