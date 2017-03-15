package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.nio.charset.StandardCharsets;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {


	private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
	private static final String DEFAULT_SIGN_ALGORITHM = "SHA256withRSA";
	private static final String CIPHER_ALGORITHM1= "RSA/ECB/PKCS1Padding";
	private static final String CIPHER_ALGORITHM2="RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
	private static final String CIPHER_ALGORITHM3="RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	private static SecureRandom secureRandom = new SecureRandom();

	public static byte[] createData(byte[][] args){
		int size = 0;
		byte[] result;
		for (byte[] b : args){
			size += b.length;
		}
		result = new byte[size];
		int pos = 0;
		for (byte[] b : args){
			for(byte b2 : b){
				result[pos] = b2;
				pos++;
			}
		}
		return result;
	}

	public static byte[] generateIv(){
		byte[] iv = new byte[16];
		secureRandom.nextBytes(iv);
		return iv;
	}

	public static byte[] generateSessionKey(){
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			SecretKey secretKey = kg.generateKey();
			return secretKey.getEncoded();
		} catch (Exception e) {
			System.out.println("Key generator: AES secret key error");
			return null;
		}
	}

	public static Message getSecureMessage(byte[][] data, byte[] secretKey, Key senderPrivKey, Key senderPubKey, Key receiverPubKey){
		byte[] randomIv = Crypto.generateIv();
		byte[] dataToDigest = null;
		if(data != null){
			byte[] dataInByteArray = Crypto.createData(data);
			dataToDigest = Crypto.createData(new byte[][] {randomIv, dataInByteArray, senderPubKey.getEncoded(), receiverPubKey.getEncoded()});
		}
		else{
			dataToDigest = Crypto.createData(new byte[][] {randomIv, senderPubKey.getEncoded(), receiverPubKey.getEncoded()});
		}
		byte[] digestToSign = Crypto.hashData(dataToDigest);
		byte[] signedData = Crypto.signData((PrivateKey)senderPrivKey, digestToSign);
		System.out.println("Crypto: signedData = " + new String(signedData, StandardCharsets.UTF_8));

		byte[] cipheredSignedData = Crypto.cipherSymmetric(secretKey, randomIv, signedData);

		byte[] cipheredDomain = null;
		if(data.length > 0){
			cipheredDomain = Crypto.cipherSymmetric(secretKey, randomIv, data[0]);
		}
		byte[] cipheredUsername= null;
		if(data.length > 1){
			cipheredUsername = Crypto.cipherSymmetric(secretKey, randomIv, data[1]);
		}
		byte[] cipheredPassword= null;
		if(data.length == 3){
			cipheredPassword = Crypto.cipherSymmetric(secretKey, randomIv, data[2]);
		}

		System.out.println("Crypto: secret key: " + new String(secretKey, StandardCharsets.UTF_8));
		byte[] cipheredSecretKey = Crypto.encrypt(secretKey, receiverPubKey);

		// PublicKey, Signature, Domain, Username, Password, SecretKey, iv
		Message m = new Message(senderPubKey, cipheredSignedData, cipheredDomain, cipheredUsername, cipheredPassword, cipheredSecretKey, randomIv);
		return m;
	}

	public static byte[] cipherSymmetric(byte [] key, byte[] iv, byte[] message) {
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encodedBytes = c.doFinal(message);
			System.out.println("cipherSymmetric: encoded done");
			return encodedBytes;
		} catch (Exception e) {
			System.out.println("cipherSymmetric: AES encryption error");
			System.out.println(e.getMessage());
			return null;
		}
	}

	public static byte[] decipherSymmetric(byte [] key, byte[] iv, byte[] message){
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] decodedBytes = c.doFinal(message);
			return decodedBytes;
		} catch (Exception e) {
			System.out.println("decipherSymmetric: AES decryption error");
			System.out.println(e.getMessage());
			return  null;
		}
	}



	public static byte[] hashData(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(DEFAULT_HASH_ALGORITHM);
			md.update(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return  md.digest();

	}	
	
	public static byte[] signData(PrivateKey privateKey, byte[] data){

		Signature rsaSignature = null;
		try {
			rsaSignature = Signature.getInstance(DEFAULT_SIGN_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			rsaSignature.initSign(privateKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		try {
			rsaSignature.update(data);
			return rsaSignature.sign();

		} catch (SignatureException e) {
			e.printStackTrace();
		}
		//TODO Maybe throw exception on signing
		return null;

	}

	public static boolean verifySign(PublicKey publicKey, byte[] data, byte[]signature){
		Signature rsaSignature = null;
		try {
			rsaSignature = Signature.getInstance(DEFAULT_SIGN_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			rsaSignature.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			rsaSignature.update(data);
			return rsaSignature.verify(signature);
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;

	}

	public static byte[] encrypt(byte[] data, Key key) {
		Cipher rsa = null;
			try {
				rsa = Cipher.getInstance(CIPHER_ALGORITHM1);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				rsa.init(Cipher.ENCRYPT_MODE, key);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				return rsa.doFinal(data);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		return null;
	}
	
	public static byte[] decrypt(byte[] ciphertext, Key key) {
			Cipher rsa = null;
			try {
				rsa = Cipher.getInstance(CIPHER_ALGORITHM1);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				rsa.init(Cipher.DECRYPT_MODE, key);
				//rsa.init(Cipher.DECRYPT_MODE, key);
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				return rsa.doFinal(ciphertext);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return null;
	}
	
}
