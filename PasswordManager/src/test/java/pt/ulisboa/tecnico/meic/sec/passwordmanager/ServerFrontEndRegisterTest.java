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
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.register(secureMessage);
    }

    @Test(expected = InvalidChallengeException.class)
    public void registerInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void registerSendSameChallengeTwiceTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongDomainNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "wrongDomain".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongDomainBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongDomainBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.domain = cipheredWrongDomain;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongUsernameNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "wrongUsername".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongUsernameBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongUsernameBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongusername = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.username = cipheredWrongusername;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.password = cipheredWrongPassword;
        serverFE.register(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void registerWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.register(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void registerNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.register(secureMessage);
    }
}
