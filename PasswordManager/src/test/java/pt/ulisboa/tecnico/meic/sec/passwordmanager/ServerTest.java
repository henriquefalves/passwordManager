package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

public class ServerTest {

    public static byte[] VALID_HASH_DOMAIN_USERNAME;
    public static byte[] INEXISTENT_HASH_DOMAIN_USERNAME;
    public static byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);

    public Server server = null;
    public Key key = null;

    public ServerTest() throws NoSuchAlgorithmException {

        byte[] VALID_DOMAIN = "a.b".getBytes(StandardCharsets.UTF_8);
        byte[] VALID_USERNAME = "name".getBytes(StandardCharsets.UTF_8);
        byte[] hashPreKey = Crypto.concatenateData(new byte[][]{VALID_DOMAIN, VALID_USERNAME});
        VALID_HASH_DOMAIN_USERNAME = Crypto.hashData(hashPreKey);

        byte[] INEXISTENT_DOMAIN = "d.e".getBytes(StandardCharsets.UTF_8);
        byte[] INEXISTENT_USERNAME = "eman".getBytes(StandardCharsets.UTF_8);
        byte[] invalidHashPreKey = Crypto.concatenateData(new byte[][]{INEXISTENT_DOMAIN, INEXISTENT_USERNAME});
        INEXISTENT_HASH_DOMAIN_USERNAME = Crypto.hashData(invalidHashPreKey);

        SecureRandom random = new SecureRandom();
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(random);
        key = keygen.generateKey();
    }

    // TODO REMOVE ALL 1!!!!
    @Before
    public void setup() throws RemoteException {
        server = new Server();
        server.register(key);
        UserData userData = new UserData();     // TODO userData in Put method must pass hashCommunicationData, signatura and wts
        userData.hashDomainUser = VALID_HASH_DOMAIN_USERNAME;
        userData.password = PASSWORD;
        userData.wts = Crypto.intToByteArray(1);
        server.put(key, userData);
    }

    @Test
    public void GetCorrectExecution() {
        try {
            UserData userData = server.get(key, VALID_HASH_DOMAIN_USERNAME);
            assertTrue(new String(userData.password, StandardCharsets.UTF_8).equals(new String(PASSWORD, StandardCharsets.UTF_8)));
        } catch (Exception e) {
            fail();
            e.printStackTrace();
        }
    }

    @Test(expected = InvalidArgumentsException.class)
    public void GetInvalidPublicKey() throws RemoteException {
        server.get(null, VALID_HASH_DOMAIN_USERNAME);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void GetInvalidHashKey() throws RemoteException {
        server.get(key, null);
    }

    @Test
    public void GetInexistentHashKey() throws RemoteException {
        UserData userData = server.get(key, INEXISTENT_HASH_DOMAIN_USERNAME);
        assertEquals("Expected null signature", null, userData.signature);
        assertEquals("Expected null hashDomainUser", null, userData.hashDomainUser);
        assertEquals("Expected null password", null, userData.password);
        assertEquals("Expected null rid", null, userData.rid);
        assertEquals("Expected null ridToCheckSign", null, userData.ridToCheckSign);
        assertArrayEquals("Expected 0 as wts", Crypto.intToByteArray(0), userData.wts);
        assertArrayEquals("Expected 0 as rank", Crypto.intToByteArray(0), userData.rank);
        assertEquals("Expected null hashCommunicationData", null, userData.hashCommunicationData);
    }

    @Test
    public void RegisterCorrectExecution() {
        try {
            server = new Server();
            server.register(key);
        } catch (Exception e) {
            fail();
            e.printStackTrace();
        }
    }

    @Test(expected = InvalidArgumentsException.class)
    public void RegisterInvalidKey() throws RemoteException {
        server.register(null);
    }

    @Test(expected = DuplicatePublicKeyException.class)
    public void RegisterDuplicateKey() throws RemoteException {
        server.register(key);
    }

    @Test
    public void PutCorrectExecutionUpdate() {
        try {
            String insertedPassword = "password2";
            byte[] newPass = insertedPassword.getBytes(StandardCharsets.UTF_8);

            UserData userDataToPut = new UserData();     // TODO userData in Put method must pass hashCommunicationData, signatura and wts
            userDataToPut.hashDomainUser = VALID_HASH_DOMAIN_USERNAME;
            userDataToPut.password = newPass;
            userDataToPut.wts = Crypto.intToByteArray(15);

            server.put(key,userDataToPut);
            UserData userDataFromGet = server.get(key, VALID_HASH_DOMAIN_USERNAME);
            String receivedPasword = new String(userDataFromGet.password, StandardCharsets.UTF_8);
            String passedPassword = new String(newPass, StandardCharsets.UTF_8);
            assertTrue(receivedPasword.equals(passedPassword));
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test(expected = InvalidArgumentsException.class)
    public void PutInvalidPublicKey() throws RemoteException {
        UserData userData = new UserData();
        userData.hashDomainUser = VALID_HASH_DOMAIN_USERNAME;
        userData.password = PASSWORD;
        server.put(null, userData);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void PutInvalidHashKey() throws RemoteException {
        UserData userData = new UserData();
        userData.hashDomainUser = null;
        userData.password = PASSWORD;
        server.put(key, userData);
    }




}