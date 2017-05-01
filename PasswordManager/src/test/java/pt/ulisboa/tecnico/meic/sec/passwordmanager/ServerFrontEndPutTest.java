package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.rmi.RemoteException;


public class ServerFrontEndPutTest extends ServerFrontEndTest {
    final byte[] DOMAIN_MOCK = "domain".getBytes();
    final byte[] USERNAME_MOCK = "username".getBytes();
    byte[] hashPreKey = Crypto.concatenateData(new byte[][]{DOMAIN_MOCK, USERNAME_MOCK});
    final  byte[] HASH_DOMAIN_USERNAME = Crypto.hashData(hashPreKey);
    final byte[] PASSWORD = "password".getBytes();

    final byte[] wts = Crypto.intToByteArray(12);
    final byte[] rid = Crypto.intToByteArray(13);
    final byte[] rank = Crypto.intToByteArray(1);
    final UserData userDataToPut = new UserData(HASH_DOMAIN_USERNAME, PASSWORD, wts, rid, rank);

    @Test
    public void putSuccessTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        // put
        Message insecureMessage = new Message(result.challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = serverPublic;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullPublicKeyOfSenderTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.publicKeySender = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void putInvalidChallengeTest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putIntersectedChallengeTest() throws RemoteException {
        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);

        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = response.challenge;
        serverFE.put(secureMessage);
    }


    @Test(expected = InvalidChallengeException.class)
    public void putSendSameChallengeTwiceTest() throws RemoteException {
        // register new user
        Message insecureMessageReg = new Message(challenge, null);
        Message secureMessageReg = Crypto.getSecureMessage(insecureMessageReg, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessageReg);

        // get new challenge
        Message insecureMessageChall = new Message();
        Message secureMessageChall = Crypto.getSecureMessage(insecureMessageChall, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessageChall);
        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);

        // put
        Message insecureMessage = new Message(result.challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        serverFE.put(secureMessage);
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void rputNullChallengeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.challenge = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = Crypto.generateIV();
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullIvTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.randomIv = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongHashDomainUsernameNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = "wrongDomain".getBytes();    // size = 11 != AES block size
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongHashDomainUsernameBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongHashDomainUsernameBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongDomain = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.userData.hashDomainUser = cipheredWrongDomain;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullHashDomainUsernameTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.hashDomainUser = null;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordNotBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.password = "wrongPassword".getBytes();        // size = 11 != AES block size
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordBlockSizeTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.password = "1234567890123456".getBytes();       // size = 16 == AES block size
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongPasswordBlockSizeCipheredTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] wrongSecretKey = Crypto.generateSessionKey();
        byte[] cipheredWrongPassword = Crypto.cipherSymmetric(wrongSecretKey, secureMessage.randomIv, "someDomain".getBytes());
        secureMessage.userData.password = cipheredWrongPassword;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putNullPasswordTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.userData.password = null;
        serverFE.put(secureMessage);
    }


    @Test(expected = CorruptedMessageException.class)
    public void putWrongSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message secureMessageWrong = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = secureMessageWrong.signature;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullSignatureTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.signature = null;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putWrongSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] badSessionKey = new byte[256];
        secureMessage.secretKey = badSessionKey;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putNullSessionKeyTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        secureMessage.secretKey = null;
        serverFE.put(secureMessage);
    }

    @Test(expected = CorruptedMessageException.class)
    public void putSwapAttributesTest() throws RemoteException {
        Message insecureMessage = new Message(challenge, userDataToPut);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        byte[] temp = secureMessage.userData.hashDomainUser;
        secureMessage.userData.hashDomainUser = secureMessage.userData.password;
        secureMessage.userData.password = temp;
        serverFE.put(secureMessage);
    }

}
