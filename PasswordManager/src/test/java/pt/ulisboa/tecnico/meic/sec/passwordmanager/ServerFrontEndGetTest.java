package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;

public class ServerFrontEndGetTest extends ServerFrontEndTest {
    final byte[] DOMAIN_MOCK = "domain".getBytes();
    final byte[] USERNAME_MOCK = "username".getBytes();
    byte[] hashPreKey = Crypto.concatenateData(new byte[][]{DOMAIN_MOCK, USERNAME_MOCK});
    final  byte[] HASH_DOMAIN_USERNAME = Crypto.hashData(hashPreKey);
    final byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);

    final byte[] wts = Crypto.intToByteArray(12);
    final byte[] rid = Crypto.intToByteArray(15);
    final byte[] rank = Crypto.intToByteArray(1);

    final UserData userDataToPut = new UserData(HASH_DOMAIN_USERNAME, PASSWORD, wts, rid, rank);

    final UserData userDataToGet = new UserData(HASH_DOMAIN_USERNAME, rid, rank);


    @Test
    public void getSuccessTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall = serverFE.getChallenge(secureMessageChall);
        Message resultChall = Crypto.checkMessage(responseChall, clientPrivate, clientPublic);

        // put
        Message insecureMessagePut = new Message(resultChall.challenge, userDataToPut);
        Message secureMessagePut = Crypto.getSecureMessage(insecureMessagePut, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessagePut);

        // get new challenge
        Message insecureMessageChall2 = new Message();
        Message secureMessageChall2 = Crypto.getSecureMessage(insecureMessageChall2, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall2 = serverFE.getChallenge(secureMessageChall2);
        Message resultChall2 = Crypto.checkMessage(responseChall2, clientPrivate, clientPublic);

        // get
        Message insecureMessage = new Message(resultChall2.challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response =  serverFE.get(secureMessage);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        if(result.challenge == null || !Arrays.equals(resultChall2.challenge, result.challenge)){
            fail("Wrong challenge");
        }

        String passwordReceived = new String(result.userData.password, StandardCharsets.UTF_8);
        String passwordExpected = new String(PASSWORD, StandardCharsets.UTF_8);

        assertEquals("DiffPasswords", passwordExpected, passwordReceived);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void getInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getIntersectedChallengeTest() throws RemoteException {
        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);

        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = response.challenge;
        serverFE.get(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void getSendSameChallengeTwiceTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall = serverFE.getChallenge(secureMessageChall);
        Message resultChall = Crypto.checkMessage(responseChall, clientPrivate, clientPublic);

        // put
        Message insecureMessagePut = new Message(resultChall.challenge, userDataToPut);
        Message secureMessagePut = Crypto.getSecureMessage(insecureMessagePut, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessagePut);

        // get new challenge
        Message insecureMessageChall2 = new Message();
        Message secureMessageChall2 = Crypto.getSecureMessage(insecureMessageChall2, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message responseChall2 = serverFE.getChallenge(secureMessageChall2);
        Message resultChall2 = Crypto.checkMessage(responseChall2, clientPrivate, clientPublic);

        // get
        Message insecureMessage = new Message(resultChall2.challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.get(secureMessage);
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongHashDomainUsernameNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = "wrongDomain".getBytes();    // size = 11 != AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongHashDomainUsernameBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongHashDomainUsernameBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.userData.hashDomainUser = cipheredWrongDomain;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullHashDomainUsernameTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = null;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.userData.password = cipheredWrongPassword;
        serverFE.get(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void getWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getWrongSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] badSessionKey = new byte[256];
        secureMessage.secretKey = badSessionKey;
        serverFE.get(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void getNullSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToGet);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.secretKey = null;
        serverFE.get(secureMessage);
    }


    // TODO fix Crypto to pass test
//    @Test(expected = CorruptedMessageException.class)
//    public void getSwapAttributesTest() throws RemoteException {
//        Message insecureMessage = new Message(challenge, userDataToGet);
//        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, clientPrivate, clientPublic, serverPublic);
//        byte[] temp = secureMessage.userData.hashDomainUser;
//        secureMessage.userData.hashDomainUser = secureMessage.userData.password;
//        secureMessage.userData.password = temp;
//        serverFE.get(secureMessage);
//    }

}
