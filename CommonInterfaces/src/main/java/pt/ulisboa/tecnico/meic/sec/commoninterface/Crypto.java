package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;

import java.security.*;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
	public static final String DEFAULT_SIGN_ALGORITHM = "SHA256withRSA";
	public static final String ASYMETRIC_CIPHER_ALGORITHM1= "RSA/ECB/PKCS1Padding";

	private static SecureRandom secureRandom = new SecureRandom();

	public static byte[] concatenateData(byte[][] args){
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

	/**
	 * @return secure random 16 bytes Initialization Vector 
	 */
	public static byte[] generateIV(){
		byte[] iv = new byte[16];
		secureRandom.nextBytes(iv);
		return iv;
	}

	/**
	 * @return AES Key with 128 bytes
	 */
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

	/**
	 * @param insecureMessage Message in plain text
	 * @return cryptographically secure Message
	 */
	public static Message getSecureMessage(Message insecureMessage, byte[] secretKey, boolean sendSecretKey, Key senderPrivKey, Key senderPubKey, Key receiverPubKey){
	    byte[] randomIv = Crypto.generateIV();

	    // argsToSign contains parameters what will be signed with senderPrivKey
        ArrayList<byte[]> argsToSign = new ArrayList<>();		// order of elements is important
		argsToSign.add(randomIv);
		argsToSign.add(senderPubKey.getEncoded());
		argsToSign.add(receiverPubKey.getEncoded());

		byte[] cipheredChallenge = null;
		if(insecureMessage.challenge != null){		// if Message in plain text contains this element, it will be ciphered and signed
			cipheredChallenge = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.challenge);
			argsToSign.add(insecureMessage.challenge);
		}

        byte[] cipheredDomain = null;
        if(insecureMessage.domain != null){		// if Message in plain text contains this element, it will be ciphered and signed
            cipheredDomain = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.domain);
			argsToSign.add(insecureMessage.domain);
        }
        byte[] cipheredUsername= null;
        if(insecureMessage.username != null){	// if Message in plain text contains this element, it will be ciphered and signed
            cipheredUsername = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.username);
			argsToSign.add(insecureMessage.username);
        }
        byte[] cipheredPassword= null;
        if(insecureMessage.password != null){	// if Message in plain text contains this element, it will be ciphered and signed
            cipheredPassword = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.password);
			argsToSign.add(insecureMessage.password);
        }

        byte[][] arrayToSign = argsToSign.toArray(new byte[0][]);	// transform array to byte array
        byte[] dataToSign = Crypto.concatenateData(arrayToSign);			// merge all data that will be sign
		byte[] signedData = Crypto.signData((PrivateKey)senderPrivKey, dataToSign);

		byte[] cipheredSignedData = Crypto.cipherSymmetric(secretKey, randomIv, signedData);

		byte[] cipheredSecretKey = null;
		if (sendSecretKey){		// if need to send the session Key
			cipheredSecretKey = Crypto.encryptAsymmetric(secretKey, receiverPubKey, ASYMETRIC_CIPHER_ALGORITHM1);
		}
		// create cryptographically secure Message
		Message secureMessage = new Message(senderPubKey, cipheredSignedData, cipheredChallenge, cipheredDomain, cipheredUsername, cipheredPassword, cipheredSecretKey, randomIv);
		return secureMessage;
	}



	// receives cryptographically secure Message, perform cryptographic operations, and return the Message in plain text
	public static Message checkMessage(Message receivedMessage, byte[] secretKey, Key receiverPriv, Key receiverPub ){
		Message messageInPlainText = new Message();

		byte[] secretKeyToDecipher = secretKey;		// use session key that receiver know (can be null)
	    if (receivedMessage.secretKey == null && secretKey == null){
            System.out.println("Crypto-checkMessage: No secret key available to decipher");
            return null;
        }
        if (receivedMessage.secretKey != null){		// check if received Message contains the session key
            secretKeyToDecipher = Crypto.decryptAsymmetric(receivedMessage.secretKey, receiverPriv, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
			messageInPlainText.secretKey = secretKeyToDecipher;
	    }

		// argsToCheckSign contains parameters what will be used to check the validity of signature
        ArrayList<byte[]> argsToCheckSign = new ArrayList<>();		// order of elements is equal to order specified in getSecureMessage()
		argsToCheckSign.add(receivedMessage.randomIv);
		argsToCheckSign.add(receivedMessage.publicKeySender.getEncoded());
		argsToCheckSign.add(receiverPub.getEncoded());

		messageInPlainText.publicKeySender = receivedMessage.publicKeySender;
		messageInPlainText.randomIv = receivedMessage.randomIv;

		byte[] decipheredChallenge = null;
		// if receivedMessage contains this element, it will be deciphered and verified in signature
		if(receivedMessage.challenge != null){
			decipheredChallenge = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.challenge);
			argsToCheckSign.add(decipheredChallenge);
			messageInPlainText.challenge = decipheredChallenge;
		}

        if (receivedMessage.domain != null){ // if receivedMessage contains this element, it will be deciphered and verified in signature
            byte[] decipheredDomain = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.domain);
			argsToCheckSign.add(decipheredDomain);
			messageInPlainText.domain = decipheredDomain;
        }
        if (receivedMessage.username != null){ // if receivedMessage contains this element, it will be deciphered and verified in signature
            byte[] decipheredUsername = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.username);
			argsToCheckSign.add(decipheredUsername);
			messageInPlainText.username = decipheredUsername;
        }
        if (receivedMessage.password != null){ // if receivedMessage contains this element, it will be deciphered and verified in signature
            byte[] decipheredPassword = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.password);
			argsToCheckSign.add(decipheredPassword);
			messageInPlainText.password = decipheredPassword;
        }

        byte[][] arrayToCheckSign = argsToCheckSign.toArray(new byte[0][]); // transform Array to byte array
        byte[] dataToCheckSignature = Crypto.concatenateData(arrayToCheckSign);

        byte[] signedData = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.signature);

        // check validity of signature
		boolean integrity = Crypto.verifySign((PublicKey) receivedMessage.publicKeySender, dataToCheckSignature, signedData);
        if (!integrity){
            System.out.println("Crypto-checkMessage: Invalid signature");
            throw new CorruptedMessageException();
        }

        System.out.println("Crypto-checkMessage: valid message");
        return messageInPlainText;
    }

	public static byte[] cipherSymmetric(byte [] key, byte[] iv, byte[] message) {
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			c.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encodedBytes = c.doFinal(message);
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
		} catch (IllegalBlockSizeException e){
			System.out.println("decipherSymmetric: Illegal block size of data");
			throw new CorruptedMessageException();
		} catch (BadPaddingException e){
			System.out.println("decipherSymmetric: Bad padding of data");
			throw new CorruptedMessageException();
		}
			catch (Exception e) {
			System.out.println("decipherSymmetric: AES decryption error");
			System.out.println(e.getClass());
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

	public static byte[] encryptAsymmetric(byte[] data, Key key,String algorithm) {
		Cipher rsa = null;
			try {
				rsa = Cipher.getInstance(algorithm);
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

	public static byte[] decryptAsymmetric(byte[] ciphertext, Key key, String algorithm) {
			Cipher rsa = null;
			try {
				rsa = Cipher.getInstance(algorithm);
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

	public static KeyPair generateKeyPairRSA2048(){
		 KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		    keyGen.initialize(2048);
		    KeyPair keypair = keyGen.genKeyPair();
		    return keypair;
	}
	
	public static SecretKey generateSecretKeyAES128(){
	KeyGenerator keyGen = null;
	try {
		keyGen = KeyGenerator.getInstance("AES");
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	keyGen.init(128); // for example
	SecretKey secretKey = keyGen.generateKey();
	return secretKey;
	}
}
