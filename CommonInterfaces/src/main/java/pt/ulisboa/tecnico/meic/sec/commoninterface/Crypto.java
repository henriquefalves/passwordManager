package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidSequenceNumberException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidSignatureException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.MissingSequenceNumException;

import java.math.BigInteger;
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

	// receives Message in plain text, perform cryptographic operations, and return cryptographically secure Message
	public static Message getSecureMessage(Message insecureMessage, byte[] passwordIv, byte[] secretKey, boolean sendSecretKey, Key senderPrivKey, Key senderPubKey, Key receiverPubKey){
	    byte[] randomIv = Crypto.generateIv();

	    // argsToSign contains parameters what will be signed with senderPrivKey
        ArrayList<byte[]> argsToSign = new ArrayList<>();		// order of elements is important
        if(passwordIv != null){
			argsToSign.add(passwordIv);
		}
		argsToSign.add(randomIv);
		argsToSign.add(senderPubKey.getEncoded());
		argsToSign.add(receiverPubKey.getEncoded());

		byte[] cipheredSeqNum = null;
		if(insecureMessage.sequenceNumber != null){		// if Message in plain text contains this element, it will be ciphered and signed
			cipheredSeqNum = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.sequenceNumber);
			argsToSign.add(insecureMessage.sequenceNumber);
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
        byte[] dataToSign = Crypto.createData(arrayToSign);			// merge all data that will be sign
		byte[] signedData = Crypto.signData((PrivateKey)senderPrivKey, dataToSign);

		byte[] cipheredSignedData = Crypto.cipherSymmetric(secretKey, randomIv, signedData);

		byte[] cipheredSecretKey = null;
		if (sendSecretKey){		// if need to send the session Key
			cipheredSecretKey = Crypto.encrypt(secretKey, receiverPubKey, ASYMETRIC_CIPHER_ALGORITHM1);
		}
		// create cryptographically secure Message
		Message secureMessage = new Message(senderPubKey, cipheredSignedData, cipheredSeqNum, cipheredDomain, cipheredUsername, cipheredPassword, cipheredSecretKey, randomIv, passwordIv);
		return secureMessage;
	}



	// receives cryptographically secure Message, perform cryptographic operations, and return the Message in plain text
	public static Message checkMessage(Message receivedMessage, BigInteger lastSeqNum, byte[] secretKey, Key receiverPriv, Key receiverPub ){
		Message messageInPlainText = new Message();

		byte[] secretKeyToDecipher = secretKey;		// use session key that receiver know (can be null)
	    if (receivedMessage.secretKey == null && secretKey == null){
            System.out.println("Crypto-checkMessage: No secret key available to decipher");
            return null;
        }
        if (receivedMessage.secretKey != null){		// check if received Message contains the session key
            secretKeyToDecipher = Crypto.decrypt(receivedMessage.secretKey, receiverPriv, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
			messageInPlainText.secretKey = secretKeyToDecipher;
	    }

		// argsToCheckSign contains parameters what will be used to check the validity of signature
        ArrayList<byte[]> argsToCheckSign = new ArrayList<>();		// order of elements is equal to order specified in getSecureMessage()
        if(receivedMessage.passwordIv != null){
			argsToCheckSign.add(receivedMessage.passwordIv);
			messageInPlainText.passwordIv = receivedMessage.passwordIv;
		}
		argsToCheckSign.add(receivedMessage.randomIv);
		argsToCheckSign.add(receivedMessage.publicKey.getEncoded());
		argsToCheckSign.add(receiverPub.getEncoded());


		byte[] decipheredSeqNum = null;
		// if receivedMessage contains this element, it will be deciphered and verified in signature
		if(receivedMessage.sequenceNumber != null){
			decipheredSeqNum = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.sequenceNumber);
			argsToCheckSign.add(decipheredSeqNum);
				messageInPlainText.sequenceNumber = decipheredSeqNum;
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
        byte[] dataToCheckSignature = Crypto.createData(arrayToCheckSign);

        byte[] signedData = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.signature);

        // check validity of signature
		boolean integrity = Crypto.verifySign((PublicKey) receivedMessage.publicKey, dataToCheckSignature, signedData);
        if (!integrity){
            System.out.println("Crypto-checkMessage: Invalid signature");
            throw new InvalidSignatureException();
        }

        if(lastSeqNum != null){		// if the receiver wants to check the sequence number
			if(decipheredSeqNum == null){
				throw new MissingSequenceNumException();
			}
			BigInteger recSeqNum = new BigInteger(decipheredSeqNum);
			BigInteger expectedSeqNum = lastSeqNum.add(BigInteger.valueOf(1));
			if(!recSeqNum.equals(expectedSeqNum)){
				System.out.println("Crypto-checkMessage: Invalid seqNumber");
				throw new InvalidSequenceNumberException();
			}
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

	public static byte[] encrypt(byte[] data, Key key,String algorithm) {
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

	public static byte[] decrypt(byte[] ciphertext, Key key, String algorithm) {
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
