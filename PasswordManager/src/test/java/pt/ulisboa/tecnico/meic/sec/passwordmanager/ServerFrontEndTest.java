package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.rmi.RemoteException;
import java.security.*;


public class ServerFrontEndTest  {
    private static PublicKey clientPublic;
    private static PrivateKey clientPrivate;
    private static PublicKey serverPublic;
    private static PrivateKey serverPrivate;
    private static byte[] sessionKey;

    private static ServerFrontEnd serverFE;

    private byte[] challenge;


    @BeforeClass
    public static void setUpClass() throws RemoteException {
    KeyPair clientKeyPair = ServerApplication.loadKeys("test.jks", "test", "ClientKeys", "12345");
    clientPrivate = clientKeyPair.getPrivate();
    clientPublic = clientKeyPair.getPublic();

    KeyPair serverKeyPair = ServerApplication.loadKeys("test.jks", "test", "ServerKeys", "12345");
    serverPrivate = serverKeyPair.getPrivate();
    serverPublic = serverKeyPair.getPublic();
    sessionKey = Crypto.generateSessionKey();

    serverFE = new ServerFrontEnd(serverPrivate, serverPublic);
    }

    @Before
    public void setUpTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessage);

        Message result = Crypto.checkMessage(response, sessionKey, clientPrivate, clientPublic);
        challenge = result.challenge;
    }


    @Test(expected = InvalidChallengeException.class)
    public void invalidChallengeTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void sendSameChallengeTwiceTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void wrongPublicKeyOfSenderTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void wrongIvTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void wrongDomainNotBlockSizeTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "wrongDomain".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void wrongDomainBlockSizeTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void wrongDomainBlockSizeCipheredTest() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.domain = cipheredWrongDomain;
        serverFE.register(secureMessage);
    }
}