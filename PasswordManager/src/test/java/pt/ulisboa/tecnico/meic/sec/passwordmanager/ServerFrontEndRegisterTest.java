package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.rmi.RemoteException;

public class ServerFrontEndRegisterTest extends ServerFrontEndTest {
    // .register

    @Test
    public void registerSuccessTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.register(secureMessage);
    }

    @Test(expected = InvalidChallengeException.class)
    public void registerInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerIntersectedChallengeTest() throws RemoteException {
        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);

        Message insecureMessage = new Message(challenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = response.challenge;
        serverFE.register(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void registerSendSameChallengeTwiceTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongHashKeyNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.hashKey = "wrongDomain".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongHashKeyBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.hashKey = "$T6ash/9012=?s56".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongHashKeyBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "somehasKeysas=?3gd".getBytes());
        secureMessage.hashKey = cipheredWrongDomain;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.password = cipheredWrongPassword;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] badSessionKey = new byte[256];
        secureMessage.secretKey = badSessionKey;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge,  null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.secretKey = null;
        serverFE.register(secureMessage);
    }

}
