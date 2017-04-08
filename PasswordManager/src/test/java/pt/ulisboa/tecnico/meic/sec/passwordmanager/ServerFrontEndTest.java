package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.BeforeClass;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;

import java.rmi.RemoteException;
import java.security.*;


public abstract class ServerFrontEndTest  {
    protected static PublicKey clientPublic;
    protected static PrivateKey clientPrivate;
    protected static PublicKey serverPublic;
    protected static PrivateKey serverPrivate;
    protected static byte[] sessionKey;

    protected static ServerFrontEnd serverFE;
    protected byte[] challenge;


    @BeforeClass
    public static void setUpClass() throws RemoteException {
    KeyPair clientKeyPair = ServerApplication.loadKeys("test.jks", "test", "ClientKeys", "12345");
    clientPrivate = clientKeyPair.getPrivate();
    clientPublic = clientKeyPair.getPublic();

    KeyPair serverKeyPair = ServerApplication.loadKeys("test.jks", "test", "ServerKeys", "12345");
    serverPrivate = serverKeyPair.getPrivate();
    serverPublic = serverKeyPair.getPublic();
    sessionKey = Crypto.generateSessionKey();

    }

    @Before
    public void setUpTest() throws RemoteException {
        serverFE = new ServerFrontEnd(serverPrivate, serverPublic);
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, clientPrivate, clientPublic, serverPublic);
        Message response = serverFE.getChallenge(secureMessage);

        Message result = Crypto.checkMessage(response, clientPrivate, clientPublic);
        challenge = result.challenge;
    }








}