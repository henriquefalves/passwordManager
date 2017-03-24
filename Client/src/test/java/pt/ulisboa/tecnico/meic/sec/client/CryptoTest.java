package pt.ulisboa.tecnico.meic.sec.client;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;

public class CryptoTest {

	private Crypto crypto;
	private PublicKey public1;
	private PrivateKey private1;
	private SecretKey secretKey;

	@Before
	public void setUp() throws Exception {
		crypto = new Crypto();
		KeyPair generateKeyPairRSA2048 = Crypto.generateKeyPairRSA2048();
		public1 = generateKeyPairRSA2048.getPublic();
		private1 = generateKeyPairRSA2048.getPrivate();
		secretKey = crypto.generateSecretKeyAES128();
	}
//TODO: Cannot Test -> Henrique
/*	@Test
	public void testMax245() {
		byte[] encryptedPass = null;
		encryptedPass = crypto.encrypt("aaaaaaaaaaaaaaccccccccaaaavvvvvaavvvvvvvvvvvvvvvvvvvvvvvvaaaaaaxxxxxxxxxxxxxxxaaaaaaaaaaaaaabbnnnnnnnnnnnnnnnnnnnnnnaaaaaaaaaaaaaaaaaaasssssssssssssssssbbbbbbbbbbbbbbdddddddddddbbbbbbbbbbbbbbbbbbjjjjjjjjjjjbbbbbssmmmmmmmmmmmmmmmmmmmmmmmmmmmvvvvvvvvvvvvvvvvvvvmmmssssssssss".getBytes(StandardCharsets.UTF_8), public1);		
		   
	}
*/
	@Test
	public void testPaddingAssymetricKey() {
		 byte[] encryptedPass = crypto.encrypt("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);

		 byte[] encryptedPass2 = crypto.encrypt("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);

		 assertFalse(Arrays.equals(encryptedPass, encryptedPass2));
	}

    @Test
    public void testPaddingAssymetricKeyTwice() {
        byte[] encryptedPass = crypto.encrypt("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
        byte[] decryptedPass = crypto.decrypt(encryptedPass, private1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);

        byte[] encryptedPass2 = crypto.encrypt("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
        byte[] decryptedPass2 = crypto.decrypt(encryptedPass2, private1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);

        assertArrayEquals(decryptedPass, decryptedPass2);
    }
	
	@Test
	public void testNormalFuntionalityAssymetricKey() {
		 byte[] beforeEncryption = "PASSWORD".getBytes(StandardCharsets.UTF_8);
		 byte[] encryptedPass = crypto.encrypt(beforeEncryption, public1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
		 byte[] decryptedPass = crypto.decrypt(encryptedPass, private1,Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
		 
		 assertArrayEquals(beforeEncryption, decryptedPass);  
	}

	@Test
	public void testNormalFuntionalitySymetricKey() {
		 byte[] beforeEncryption = "domain".getBytes(StandardCharsets.UTF_8);
		 byte[] encryptedPass = crypto.encrypt(beforeEncryption, secretKey,"AES");
		 byte[] decryptedPass = crypto.decrypt(encryptedPass, secretKey,"AES");
		 
		 assertArrayEquals(beforeEncryption, decryptedPass);  
	}
	
	@Test
	public void testNoIVSymetricKey() {
		 byte[] beforeEncryption = "domain".getBytes(StandardCharsets.UTF_8);
		 byte[] encryptedPass = crypto.encrypt(beforeEncryption, secretKey,"AES");
		 byte[] encryptedPass2 = crypto.encrypt(beforeEncryption, secretKey,"AES");

		 assertArrayEquals(encryptedPass, encryptedPass2);  
	}
	
//	//TODO: Unable to catch exception
//	@Test
//	public void testIntegritySymetricKey() {
//		 byte[] beforeEncryption = "domain".getBytes(StandardCharsets.UTF_8);
//		 byte[] encryptedPass = crypto.encrypt(beforeEncryption, secretKey,"AES");
//		 encryptedPass[5]=50;
//		 byte[] decryptedPass = crypto.decrypt(encryptedPass, secretKey,"AES");
//		 assertFalse(Arrays.equals(beforeEncryption, decryptedPass));
//
//	}
}
