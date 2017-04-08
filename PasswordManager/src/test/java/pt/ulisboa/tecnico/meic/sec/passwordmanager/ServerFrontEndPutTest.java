package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.rmi.RemoteException;


public class ServerFrontEndPutTest extends ServerFrontEndTest {
    final byte[] DOMAIN = "domain".getBytes();
    final byte[] USERNAME = "username".getBytes();
    final byte[] PASSWORD = "password".getBytes();

    @Test
    public void putSuccessTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null, null, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        // put
        Message insecureMessage = new Message(result.challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void putInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void putSendSameChallengeTwiceTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null, null, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        // put
        Message insecureMessage = new Message(result.challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void rputNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongDomainNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "wrongDomain".getBytes();    // size = 11 != AES block size
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongDomainBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongDomainBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.domain = cipheredWrongDomain;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullDomainTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongUsernameNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "wrongUsername".getBytes();        // size = 11 != AES block size
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongUsernameBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongUsernameBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongusername = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.username = cipheredWrongusername;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullUsernameTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = null;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.password = cipheredWrongPassword;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putNullPasswordTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.put(secureMessage);
    }
}
