package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidSequenceNumberException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidSignatureException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {


public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
	public static final String DEFAULT_SIGN_ALGORITHM = "SHA256withRSA";
	public static final String ASYMETRIC_CIPHER_ALGORITHM1= "RSA/ECB/PKCS1Padding";
	public static final String ASYMETRIC_CIPHER_ALGORITHM2="RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
	public static final String ASYMETRIC_CIPHER_ALGORITHM3="RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	public static final String SYMETRIC_CIPHER_ALGORITHM="AES/CBC/PKCS5Padding";
	public static final String SYMETRIC_CIPHER_ALGORITHM2="AES/CTR/NoPadding";	


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

	public static Message getSecureMessage(Message insecureMessage, byte[] passwordIv, byte[] secretKey, Key senderPrivKey, Key senderPubKey, Key receiverPubKey){
	    byte[] randomIv = Crypto.generateIv();

        ArrayList<byte[]> argsToHast = new ArrayList<>();		// order of adds is important
        if(passwordIv != null){
			argsToHast.add(passwordIv);
		}
        argsToHast.add(randomIv);
        argsToHast.add(senderPubKey.getEncoded());
        argsToHast.add(receiverPubKey.getEncoded());

		byte[] cipheredSeqNum = null;
		if(insecureMessage.sequenceNumber != null){
			cipheredSeqNum = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.sequenceNumber);
			argsToHast.add(insecureMessage.sequenceNumber);
		}

        byte[] cipheredDomain = null;
        if(insecureMessage.domain != null){
            cipheredDomain = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.domain);
            argsToHast.add(insecureMessage.domain);
        }
        byte[] cipheredUsername= null;
        if(insecureMessage.username != null){
            cipheredUsername = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.username);
            argsToHast.add(insecureMessage.username);
        }
        byte[] cipheredPassword= null;
        if(insecureMessage.password != null){
            cipheredPassword = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.password);
            argsToHast.add(insecureMessage.password);
        }

        byte[][] arrayToHash = argsToHast.toArray(new byte[0][]);
        byte[] dataToSign = Crypto.createData(arrayToHash);
		byte[] signedData = Crypto.signData((PrivateKey)senderPrivKey, dataToSign);

		byte[] cipheredSignedData = Crypto.cipherSymmetric(secretKey, randomIv, signedData);

		byte[] cipheredSecretKey = Crypto.encrypt(secretKey, receiverPubKey, ASYMETRIC_CIPHER_ALGORITHM1);

		// PublicKey, Signature, seqNum, Domain, Username, Password, SecretKey, iv, passwordIv
		Message secureMessage = new Message(senderPubKey, cipheredSignedData, cipheredSeqNum, cipheredDomain, cipheredUsername, cipheredPassword, cipheredSecretKey, randomIv, passwordIv);
		return secureMessage;
	}




	public static Message checkMessage(Message receivedMessage, BigInteger lastSeqNum, byte[] secretKey, Key receiverPriv, Key receiverPub ){
	    byte[] secretKeyToDecipher = secretKey;
	    if (receivedMessage.secretKey == null && secretKey == null){
            System.out.println("Crypto-checkMessage: No secret key available to decipher");
            return null;
        }
        if (receivedMessage.secretKey != null){
            secretKeyToDecipher = Crypto.decrypt(receivedMessage.secretKey, receiverPriv, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
        }

        Message cleanMessage = new Message();

        ArrayList<byte[]> argsToHast = new ArrayList<>();
        if(receivedMessage.passwordIv != null){
			argsToHast.add(receivedMessage.passwordIv);
			cleanMessage.passwordIv = receivedMessage.passwordIv;
		}
        argsToHast.add(receivedMessage.randomIv);
        argsToHast.add(receivedMessage.publicKey.getEncoded());
        argsToHast.add(receiverPub.getEncoded());


		byte[] decipheredSeqNum = null;
		if(lastSeqNum != null || receivedMessage.sequenceNumber != null){
			// add seqNum
			decipheredSeqNum = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.sequenceNumber);
			argsToHast.add(decipheredSeqNum);
			if(receivedMessage.sequenceNumber != null){
				cleanMessage.sequenceNumber = decipheredSeqNum;
			}
		}

        if (receivedMessage.domain != null){
            // add domain
            byte[] decipheredDomain = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.domain);
            argsToHast.add(decipheredDomain);
			cleanMessage.domain = decipheredDomain;
        }
        if (receivedMessage.username != null){
            // add username
            byte[] decipheredUsername = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.username);
            argsToHast.add(decipheredUsername);
			cleanMessage.username = decipheredUsername;
        }
        if (receivedMessage.password != null){
            // add password
            byte[] decipheredPassword = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.password);
            argsToHast.add(decipheredPassword);
			cleanMessage.password = decipheredPassword;
        }

        byte[][] arrayToHash = argsToHast.toArray(new byte[0][]);
        byte[] dataToHash = Crypto.createData(arrayToHash);

        byte[] signedData = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.signature);

		boolean integrity = Crypto.verifySign((PublicKey) receivedMessage.publicKey, dataToHash, signedData);
        if (!integrity){
            System.out.println("Crypto-checkMessage: Invalid signature");
            throw new InvalidSignatureException();
        }

        if(lastSeqNum != null){
			BigInteger recSeqNum = new BigInteger(decipheredSeqNum);
			BigInteger expectedSeqNum = lastSeqNum.add(BigInteger.valueOf(1));
			if(!recSeqNum.equals(expectedSeqNum)){
				System.out.println("Crypto-checkMessage: Invalid seqNumber");
				throw new InvalidSequenceNumberException();
			}
		}
        System.out.println("Crypto-checkMessage: valid message");
        return cleanMessage;
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
	
	public byte[] encryptSymetrickey(byte[] data, Key key,String algorithm, IvParameterSpec iv) {
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
				rsa.init(Cipher.ENCRYPT_MODE, key, iv);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
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
	
	public byte[] decryptSymetricKey(byte[] ciphertext, Key key, String algorithm,IvParameterSpec iv) {
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
	
	
	public  byte[] keyDerivationFunction( final char[] password, final byte[] salt ) {

			SecretKeyFactory skf = null;
			try {
				skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			int keyLength = 256;
			int iterations=1000;
			int saltLength=32;
			PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength  );
			SecretKey key = null;
			try {
				key = skf.generateSecret( spec );
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte[] res = key.getEncoded( );
			return res;

	
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
