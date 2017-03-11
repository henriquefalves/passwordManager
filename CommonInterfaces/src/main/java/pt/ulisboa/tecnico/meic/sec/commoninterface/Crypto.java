package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Crypto {


	private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
	private static final String DEFAULT_SIGN_ALGORITHM = "SHA256withRSA";
	private static final String CIPHER_ALGORITHM1= "RSA/ECB/PKCS1Padding";
	private static final String CIPHER_ALGORITHM2="RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
	private static final String CIPHER_ALGORITHM3="RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; 
	public byte[] hashData(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(DEFAULT_HASH_ALGORITHM);
			md.update(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return  md.digest();

	}	
	
	public byte[] signData(PrivateKey privateKey, byte[] data){

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

	public boolean verifySign(PublicKey publicKey, byte[] data, byte[]signature){
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

	public byte[] encrypt(byte[] data, Key key) {
		Cipher rsa = null;
			try {
				rsa = Cipher.getInstance("CIPHER_ALGORITHM1");
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
	
	public byte[] decrypt(byte[] ciphertext, Key key) {
			Cipher rsa = null;
			try {
				rsa = Cipher.getInstance("CIPHER_ALGORITHM1");
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
	
}
