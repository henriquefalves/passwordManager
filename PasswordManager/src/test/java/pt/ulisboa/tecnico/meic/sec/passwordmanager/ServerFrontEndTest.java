package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;

import static org.junit.Assert.*;

/**
 * Created by constantin on 3/24/17.
 */
public class ServerFrontEndTest {
    private static PublicKey clientPublic;
    private static PrivateKey clientPrivate;
    private static PublicKey serverPublic;
    private static PrivateKey serverPrivate;

    private static ServerFrontEnd serverFE;
    private BigInteger nextSeqNum;


    @BeforeClass
    public static void setUpClass(){
    KeyPair clientKeyPair = ServerApplication.loadKeys("test.jks", "test", "ClientKeys", "12345");
    clientPrivate = clientKeyPair.getPrivate();
    clientPublic = clientKeyPair.getPublic();

    KeyPair serverKeyPair = ServerApplication.loadKeys("test.jks", "test", "ServerKeys", "12345");
    serverPrivate = serverKeyPair.getPrivate();
    serverPublic = serverKeyPair.getPublic();
    }

    @Before
    public void setUpTest() throws RemoteException {
        serverFE = new ServerFrontEnd(serverPrivate, serverPublic);

        Message insecureMessage = new Message(null, null, null, null);
        byte[] sessionKey = Crypto.generateSessionKey();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, sessionKey, true, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getSequenceNumber(secureMessage);

        Message result = Crypto.checkMessage(response, null, sessionKey, clientPrivate, clientPublic);
        nextSeqNum  = new BigInteger(result.sequenceNumber);
        System.out.println("SFEtest-setUpTest: seqNum = " + nextSeqNum);
    }


    @Test
    public void test(){
        System.out.println("SFEtest-test: seqNum = " + nextSeqNum);
        assertEquals(1, 1);
    }
}