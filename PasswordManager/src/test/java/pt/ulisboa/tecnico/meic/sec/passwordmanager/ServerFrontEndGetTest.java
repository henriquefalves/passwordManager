package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;

public class ServerFrontEndGetTest extends ServerFrontEndTest {
    final byte[] DOMAIN = "domain".getBytes();
    final byte[] USERNAME = "username".getBytes();
    final byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);


    @Test
    public void getSuccessTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null, null, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall = serverFE.getChallenge(secureMessageChall);
        Message resultChall = Crypto.checkMessage(responseChall, clientPrivate, clientPublic);

        // put
        Message insecureMessagePut = new Message(resultChall.challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessagePut = Crypto.getSecureMessage(insecureMessagePut, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessagePut);

        // get new challenge
        Message insecureMessageChall2 = new Message();
        Message secureMessageChall2 = Crypto.getSecureMessage(insecureMessageChall2, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall2 = serverFE.getChallenge(secureMessageChall2);
        Message resultChall2 = Crypto.checkMessage(responseChall2, clientPrivate, clientPublic);

        // get
        Message insecureMessage = new Message(resultChall2.challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response =  serverFE.get(secureMessage);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        if(result.challenge == null || !Arrays.equals(resultChall2.challenge, result.challenge)){
            fail("Wrong challenge");
        }

        String passwordReceived = new String(result.password, StandardCharsets.UTF_8);
        String passwordExpected = new String(PASSWORD, StandardCharsets.UTF_8);

        assertEquals("DiffPasswords", passwordExpected, passwordReceived);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void getInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getIntersectedChallengeTest() throws RemoteException {
        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);

        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = response.challenge;
        serverFE.get(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void getSendSameChallengeTwiceTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null, null, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall = serverFE.getChallenge(secureMessageChall);
        Message resultChall = Crypto.checkMessage(responseChall, clientPrivate, clientPublic);

        // put
        Message insecureMessagePut = new Message(resultChall.challenge, DOMAIN, USERNAME, PASSWORD);
        Message secureMessagePut = Crypto.getSecureMessage(insecureMessagePut, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessagePut);

        // get new challenge
        Message insecureMessageChall2 = new Message();
        Message secureMessageChall2 = Crypto.getSecureMessage(insecureMessageChall2, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall2 = serverFE.getChallenge(secureMessageChall2);
        Message resultChall2 = Crypto.checkMessage(responseChall2, clientPrivate, clientPublic);

        // get
        Message insecureMessage = new Message(resultChall2.challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.get(secureMessage);
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongDomainNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "wrongDomain".getBytes();    // size = 11 != AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongDomainBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongDomainBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.domain = cipheredWrongDomain;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullDomainTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.domain = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongUsernameNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "wrongUsername".getBytes();        // size = 11 != AES block size
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongUsernameBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongUsernameBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongusername = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.username = cipheredWrongusername;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getNullUsernameTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.username = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.password = cipheredWrongPassword;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] badSessionKey = new byte[256];
        secureMessage.secretKey = badSessionKey;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.secretKey = null;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getSwapAttributesTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, DOMAIN, USERNAME, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] temp = secureMessage.username;
        secureMessage.username = secureMessage.domain;
        secureMessage.domain = temp;
        serverFE.get(secureMessage);
    }
}
