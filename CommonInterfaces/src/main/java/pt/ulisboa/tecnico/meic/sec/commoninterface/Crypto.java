package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDigitalSignature;

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
    public static final String ASYMETRIC_CIPHER_ALGORITHM1 = "RSA/ECB/PKCS1Padding";

    private static SecureRandom secureRandom = new SecureRandom();

    public static byte[] concatenateData(byte[][] args) {
        int size = 0;
        byte[] result;
        for (byte[] b : args) {
            size += b.length;
        }
        result = new byte[size];
        int pos = 0;
        for (byte[] b : args) {
            for (byte b2 : b) {
                result[pos] = b2;
                pos++;
            }
        }
        return result;
    }

    /**
     * @return secure random 16 bytes Initialization Vector
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * @return AES Key with 128 bytes
     */
    public static byte[] generateSessionKey() {
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


    private static UserData addContentOfUserDataToSign(UserData insecureUserData, ArrayList<byte[]> argsToSign, byte[] secretKey, byte[] randomIv) {
        UserData cipheredUserData = new UserData();

        if (insecureUserData.signature != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.signature = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.signature);
            argsToSign.add(insecureUserData.signature);
        }
        if (insecureUserData.hashDomainUser != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.hashDomainUser = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.hashDomainUser);
            argsToSign.add(insecureUserData.hashDomainUser);
        }
        if (insecureUserData.password != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.password = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.password);
            argsToSign.add(insecureUserData.password);
        }
        if (insecureUserData.rid != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.rid = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.rid);
            argsToSign.add(insecureUserData.rid);
        }
        if (insecureUserData.wts != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.wts = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.wts);
            argsToSign.add(insecureUserData.wts);
        }
        if (insecureUserData.hashCommunicationData != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredUserData.hashCommunicationData = Crypto.cipherSymmetric(secretKey, randomIv, insecureUserData.hashCommunicationData);
            argsToSign.add(insecureUserData.hashCommunicationData);
        }
        return cipheredUserData;
    }

    /**
     * @param insecureMessage Message in plain text
     * @return cryptographically secure Message
     */
    public static Message getSecureMessage(Message insecureMessage, byte[] secretKey, Key senderPrivKey, Key senderPubKey, Key receiverPubKey) {
        byte[] randomIv = Crypto.generateIV();

        ArrayList<byte[]> communicationDataToHash = new ArrayList<>();        // order of elements is important
        communicationDataToHash.add(randomIv);
        communicationDataToHash.add(senderPubKey.getEncoded());
        communicationDataToHash.add(receiverPubKey.getEncoded());

        byte[] cipheredChallenge = null;
        if (insecureMessage.challenge != null) {        // if Message in plain text contains this element, it will be ciphered and signed
            cipheredChallenge = Crypto.cipherSymmetric(secretKey, randomIv, insecureMessage.challenge);
            communicationDataToHash.add(insecureMessage.challenge);
        }

        byte[][] arrayToHash = communicationDataToHash.toArray(new byte[0][]);    // transform array to byte array
        byte[] commDataToHash = Crypto.concatenateData(arrayToHash);            // merge all data that will be hashed
        byte [] hashedCommunicationData = Crypto.hashData(commDataToHash);

        // argsToSign contains parameters what will be signed with senderPrivKey
        ArrayList<byte[]> argsToSign = new ArrayList<>();        // order of elements is important
        argsToSign.add(hashedCommunicationData);

        UserData cipheredUserData = null;
        if (insecureMessage.userData != null){
            cipheredUserData = addContentOfUserDataToSign(insecureMessage.userData, argsToSign, secretKey, randomIv);
        }

        byte[][] arrayToSign = argsToSign.toArray(new byte[0][]);    // transform array to byte array
        byte[] dataToSign = Crypto.concatenateData(arrayToSign);            // merge all data that will be sign
        byte[] signedData = Crypto.signData((PrivateKey) senderPrivKey, dataToSign);

        byte[] cipheredSignedData = Crypto.cipherSymmetric(secretKey, randomIv, signedData);
        byte[] cipheredSecretKey = Crypto.encryptAsymmetric(secretKey, receiverPubKey, ASYMETRIC_CIPHER_ALGORITHM1);

        // create cryptographically secure Message
        Message secureMessage = new Message(senderPubKey, cipheredSignedData, cipheredChallenge, cipheredSecretKey, randomIv, cipheredUserData);
        return secureMessage;
    }




    
    // receives cryptographically secure Message, perform cryptographic operations, and return the Message in plain text
    public static Message checkMessage(Message receivedMessage, Key receiverPriv, Key receiverPub) {
        if (receivedMessage.randomIv == null || receivedMessage.signature == null || receivedMessage.secretKey == null) {
            throw new CorruptedMessageException();
        }

        Message messageInPlainText = new Message();

        byte[] secretKeyToDecipher = Crypto.decryptAsymmetric(receivedMessage.secretKey, receiverPriv, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
        messageInPlainText.secretKey = secretKeyToDecipher;

        ArrayList<byte[]> hashedCommDataToCheckSign = new ArrayList<>();
        hashedCommDataToCheckSign.add(receivedMessage.randomIv);
        hashedCommDataToCheckSign.add(receivedMessage.publicKeySender.getEncoded());
        hashedCommDataToCheckSign.add(receiverPub.getEncoded());

        messageInPlainText.publicKeySender = receivedMessage.publicKeySender;
        messageInPlainText.randomIv = receivedMessage.randomIv;

        byte[] decipheredChallenge = null;

        // if existent, add challenge to signature verification
        if (receivedMessage.challenge != null) {
            decipheredChallenge = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.challenge);
            hashedCommDataToCheckSign.add(decipheredChallenge);
            messageInPlainText.challenge = decipheredChallenge;
        }

        byte[][] arrayToHash = hashedCommDataToCheckSign.toArray(new byte[0][]);    // transform array to byte array
        byte[] commDataToCheckSign = Crypto.concatenateData(arrayToHash);            // merge all data that will be hashed
        byte [] hashedCommunicationDataToCheckSign = Crypto.hashData(commDataToCheckSign);

        // argsToCheckSign contains parameters what will be used to check the validity of signature
        ArrayList<byte[]> argsToCheckSign = new ArrayList<>();
        argsToCheckSign.add(hashedCommunicationDataToCheckSign);
        if(receivedMessage.userData != null){
            messageInPlainText.userData = getContentOfUserDataCheckToSign(receivedMessage.userData,
                    argsToCheckSign, secretKeyToDecipher, receivedMessage.randomIv);
        }
        messageInPlainText.currentCommunicationData = hashedCommunicationDataToCheckSign;

        // transform Array to byte array
        byte[][] arrayToCheckSign = argsToCheckSign.toArray(new byte[0][]);
        byte[] dataToCheckSignature = Crypto.concatenateData(arrayToCheckSign);

        byte[] signedData = Crypto.decipherSymmetric(secretKeyToDecipher, receivedMessage.randomIv, receivedMessage.signature);

        // check validity of signature
        boolean integrity = Crypto.verifySign((PublicKey) receivedMessage.publicKeySender, dataToCheckSignature, signedData);
        if (!integrity) {
            throw new CorruptedMessageException();
        }
        return messageInPlainText;
    }


    private static UserData getContentOfUserDataCheckToSign(UserData cipheredUserData, ArrayList<byte[]> argsToCheckSign, byte[] secretKeyToDecipher, byte[] randomIv) {
        UserData decipheredUserData = new UserData();

        if (cipheredUserData.signature != null) {
            byte[] decipheredSignature = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.signature);
            argsToCheckSign.add(decipheredSignature);
            decipheredUserData.signature = decipheredSignature;
        }
        if (cipheredUserData.hashDomainUser != null) {
            byte[] decipheredHashDomainUser = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.hashDomainUser);
            argsToCheckSign.add(decipheredHashDomainUser);
            decipheredUserData.hashDomainUser = decipheredHashDomainUser;
        }
        if (cipheredUserData.password != null) {
            byte[] decipheredPassword = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.password);
            argsToCheckSign.add(decipheredPassword);
            decipheredUserData.password = decipheredPassword;
        }
        if (cipheredUserData.rid != null) {
            byte[] decipheredRid = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.rid);
            argsToCheckSign.add(decipheredRid);
            decipheredUserData.rid = decipheredRid;
        }
        if (cipheredUserData.wts != null) {
            byte[] decipheredWts = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.wts);
            argsToCheckSign.add(decipheredWts);
            decipheredUserData.wts = decipheredWts;
        }
        if (cipheredUserData.hashCommunicationData != null) {
            byte[] decipheredHashCommunicationData = Crypto.decipherSymmetric(secretKeyToDecipher, randomIv, cipheredUserData.hashCommunicationData);
            argsToCheckSign.add(decipheredHashCommunicationData);
            decipheredUserData.hashCommunicationData = decipheredHashCommunicationData;
        }
        return decipheredUserData;
    }


    public static byte[] cipherSymmetric(byte[] key, byte[] iv, byte[] message) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            c.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encodedBytes = c.doFinal(message);
            return encodedBytes;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static byte[] decipherSymmetric(byte[] key, byte[] iv, byte[] message) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            c.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decodedBytes = c.doFinal(message);
            return decodedBytes;
        } catch (IllegalBlockSizeException e) {
            System.out.println("decipherSymmetric: Illegal block size of data");
            throw new CorruptedMessageException();
        } catch (BadPaddingException e) {
            System.out.println("decipherSymmetric: Bad padding of data");
            throw new CorruptedMessageException();
        } catch (Exception e) {
            System.out.println("decipherSymmetric: AES decryption error");
            System.out.println(e.getClass());
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static byte[] hashData(byte[] data) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(DEFAULT_HASH_ALGORITHM);
            md.update(data);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("INVALID ALGORITHM FOR HASHING");
        }
        return md.digest();

    }

    public static byte[] signData(PrivateKey privateKey, byte[] data) {
        Signature rsaSignature = null;
        try {
            rsaSignature = Signature.getInstance(DEFAULT_SIGN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm for Signing");
        }
        try {
            rsaSignature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            System.out.println("The private Key used on the digital signature is invalid");
        }
        try {
            rsaSignature.update(data);
            return rsaSignature.sign();

        } catch (SignatureException e) {
            System.out.println("The data to sign is invalid to be digitally signed");
        }
        throw new InvalidDigitalSignature();
    }

    public static boolean verifySign(PublicKey publicKey, byte[] data, byte[] signature) {
        Signature rsaSignature = null;
        try {
            rsaSignature = Signature.getInstance(DEFAULT_SIGN_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm to validated Signature");

        }
        try {
            rsaSignature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid public Key to verify digital signature ");

        }
        try {
            rsaSignature.update(data);
            return rsaSignature.verify(signature);
        } catch (SignatureException e) {
            System.out.println("Invalid digital signature ");

        }

        return false;
    }

    public static byte[] encryptAsymmetric(byte[] data, Key key, String algorithm) {
        Cipher rsa = null;
        try {
            rsa = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm to encrypt Asymmetrically");
        } catch (NoSuchPaddingException e) {
            System.out.println("Invalid Algorithm to encrypt Asymmetrically");
        }
        try {
            rsa.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key to encrypt Asymmetrically");
        }
        try {
            return rsa.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            System.out.println("Invalid data to encrypt Asymmetrically");
        } catch (BadPaddingException e) {
            System.out.println("Error encrypting data  Asymmetrically");

        }

        return null;
    }

    public static byte[] decryptAsymmetric(byte[] ciphertext, Key key, String algorithm) {
        Cipher rsa = null;
        try {
            rsa = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {

            System.out.println("Invalid Algorithm to decrypt Asymmetrically");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            rsa.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException e1) {

            System.out.println("Invalid key to decrypt Asymmetrically");
            e1.printStackTrace();
        }
        try {
            return rsa.doFinal(ciphertext);
        } catch (IllegalBlockSizeException e) {
            System.out.println("decryptAsymmetric: Illegal block size of data");
            throw new CorruptedMessageException();
        } catch (BadPaddingException e) {
            System.out.println("decryptAsymmetric: Bad padding of data");
            throw new CorruptedMessageException();
        }
    }

    public static KeyPair generateKeyPairRSA2048() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm to generated Asymmetric Key");
        }
        keyGen.initialize(2048);
        KeyPair keypair = keyGen.genKeyPair();
        return keypair;
    }

    public static SecretKey generateSecretKeyAES128() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm to generated Symmetric Key");

        }
        keyGen.init(128); // for example
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }

    /** Necessary to cipher integers
     * @param encodedValue
     * @return
     */
    public static int byteArrayToInt(byte[] encodedValue) {
        int value = (encodedValue[3] << (Byte.SIZE * 3));
        value |= (encodedValue[2] & 0xFF) << (Byte.SIZE * 2);
        value |= (encodedValue[1] & 0xFF) << (Byte.SIZE * 1);
        value |= (encodedValue[0] & 0xFF);
        return value;
    }

     /** Necessary  to cipher integers
     * @param value
     * @return
     */
    public static byte[] intToByteArray(int value) {
        byte[] encodedValue = new byte[Integer.SIZE / Byte.SIZE];
        encodedValue[3] = (byte) (value >> Byte.SIZE * 3);
        encodedValue[2] = (byte) (value >> Byte.SIZE * 2);
        encodedValue[1] = (byte) (value >> Byte.SIZE);
        encodedValue[0] = (byte) value;
        return encodedValue;
    }
}
