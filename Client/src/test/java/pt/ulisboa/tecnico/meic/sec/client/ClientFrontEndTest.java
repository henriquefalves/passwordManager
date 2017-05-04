package pt.ulisboa.tecnico.meic.sec.client;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class ClientFrontEndTest {

    private static final String USERALIAS = "user";
    private static final String SERVER_ALIAS = "server";

    byte[] originalHashDomainUser = "domainUser".getBytes(StandardCharsets.UTF_8);
    byte[] originalPassword = "password".getBytes(StandardCharsets.UTF_8);

    byte[] newHashDomainUser = "newDomainUser".getBytes(StandardCharsets.UTF_8);
    byte[] newPassword = "newPassword".getBytes(StandardCharsets.UTF_8);


    Key myPublicKey;
    ClientFrontEnd client;


    @Test
    public void oneReadPasswordCorrectTest() throws RemoteException {
        byte[] obtainedPassword = client.get(myPublicKey, originalHashDomainUser);
        assertEquals(obtainedPassword, originalPassword);
    }

    @Test
    public void oneReadRidCorrectTest() throws  RemoteException {
        client.get(myPublicKey, originalHashDomainUser);
        assertTrue(client.rid == 1);
    }

    @Test
    public void twoReadRidCorrectTest() throws  RemoteException {
        client.put(myPublicKey, newHashDomainUser, newPassword);
        client.get(myPublicKey, originalHashDomainUser);
        assertTrue(client.rid == 2);
    }

    @Test
    public void twoReadPasswordCorrectTest() throws RemoteException {
        client.put(myPublicKey, newHashDomainUser, newPassword);
        byte[] obtainedPassword = client.get(myPublicKey, originalHashDomainUser);
        assertEquals(obtainedPassword, newPassword);
    }

    @Test
    public void receiveDifferentAnswersCorrectTest() throws RemoteException {
        client.put(myPublicKey, originalHashDomainUser, newPassword);

        //here we should tell servers to answer differently when asked
        //using mocks. i still don't know how to do that

        client.get(myPublicKey, originalHashDomainUser);
    }













    @Before
    public void populateServer() throws RemoteException {
        client.put(myPublicKey, originalHashDomainUser, originalPassword);
    }

    //TODO : add remote servers
    @BeforeClass
    public void init(ArrayList<String> remoteServerNames) throws IOException, NotBoundException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        client = new ClientFrontEnd("1", remoteServerNames);

        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("JCEKS");
        } catch (KeyStoreException e) {
            System.out.println("Unable to create Keystore");
        }

        String keystoreName = "henriqueKeyStore.jks";
        String keystorePassword = "henrique123";

        keystore = loadKeystore(keystore , keystoreName, keystorePassword.toCharArray());
        Key key = keystore.getKey(USERALIAS,  "".toCharArray());

        Key myPrivateKey=null;
        myPublicKey=null;

        if (key instanceof PrivateKey) {

            // Get certificate of public key
            java.security.cert.Certificate cert = null;
            cert = keystore.getCertificate(USERALIAS);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();
        }

        PublicKey serverPublicKey = null;
        serverPublicKey= keystore.getCertificate(SERVER_ALIAS).getPublicKey();

        client.init(myPrivateKey, myPublicKey, serverPublicKey);
        client.register(myPublicKey);

    }

    private KeyStore loadKeystore(KeyStore keystore, String keyStoreName, char[] passwordKeyStore) throws NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = keystore;

        FileInputStream fis=null;
        fis = new FileInputStream(keyStoreName);
        ks.load(fis, passwordKeyStore);
        if(fis != null )
            fis.close();
        return ks;
    }

}
