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

	@Test
	public void signatureSwapOrderTest(){
		byte[] dataToSign1 = "AAAAABBBBB".getBytes();
		byte[] dataToSign2 = "BBBBBAAAAA".getBytes();

		byte[] signature1 = Crypto.signData(private1, dataToSign1);
		byte[] signature2 = Crypto.signData(private1, dataToSign2);

		assertFalse(Arrays.equals(signature1, signature2));
		assertFalse(Crypto.verifySign(public1, dataToSign2, signature1));
		assertFalse(Crypto.verifySign(public1, dataToSign1, signature2));
	}

	@Test
	public void testPaddingAssymetricKey() {
		 byte[] encryptedPass = crypto.encryptAsymmetric("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);

		 byte[] encryptedPass2 = crypto.encryptAsymmetric("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);

		 assertFalse(Arrays.equals(encryptedPass, encryptedPass2));
	}

    @Test
    public void testPaddingAssymetricKeyTwice() {
        byte[] encryptedPass = crypto.encryptAsymmetric("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);
        byte[] decryptedPass = crypto.decryptAsymmetric(encryptedPass, private1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);

        byte[] encryptedPass2 = crypto.encryptAsymmetric("PASSWORD".getBytes(StandardCharsets.UTF_8), public1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);
        byte[] decryptedPass2 = crypto.decryptAsymmetric(encryptedPass2, private1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);

        assertArrayEquals(decryptedPass, decryptedPass2);
    }
	
	@Test
	public void testNormalFunctionalityAsymmetricKey() {
		 byte[] beforeEncryption = "PASSWORD".getBytes(StandardCharsets.UTF_8);
		 byte[] encryptedPass = crypto.encryptAsymmetric(beforeEncryption, public1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);
		 byte[] decryptedPass = crypto.decryptAsymmetric(encryptedPass, private1,Crypto.ASYMMETRIC_CIPHER_ALGORITHM1);
		 
		 assertArrayEquals(beforeEncryption, decryptedPass);  
	}

	@Test
	public void testNormalFunctionalitySymmetricKey() {
		byte[] beforeEncryption = "domain".getBytes(StandardCharsets.UTF_8);
		byte[] encryptedPass = crypto.encryptAsymmetric(beforeEncryption, secretKey,"AES");
		byte[] decryptedPass = crypto.decryptAsymmetric(encryptedPass, secretKey,"AES");
		 
		assertArrayEquals(beforeEncryption, decryptedPass);
	}
	
	@Test
	public void testNoIVSymmetricKey() {
		 byte[] beforeEncryption = "domain".getBytes(StandardCharsets.UTF_8);
		 byte[] encryptedPass = crypto.encryptAsymmetric(beforeEncryption, secretKey,"AES");
		 byte[] encryptedPass2 = crypto.encryptAsymmetric(beforeEncryption, secretKey,"AES");

		 assertArrayEquals(encryptedPass, encryptedPass2);  
	}
}
