package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;

import static org.junit.Assert.*;



public class ServerFrontEndTest {
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
    public void setUpTest() throws RemoteException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessage);

        Message result = Crypto.checkMessage(response, sessionKey, clientPrivate, clientPublic);
        challenge = result.challenge;
    }


    @Test(expected = InvalidChallengeException.class)
    public void invalidChallengetest() throws RemoteException {
        byte[] invalidChallenge = "invalidChallenge".getBytes();
        Message insecureMessage = new Message(invalidChallenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, true, clientPrivate, clientPublic, serverPublic);
        serverFE.register(secureMessage);
    }



}