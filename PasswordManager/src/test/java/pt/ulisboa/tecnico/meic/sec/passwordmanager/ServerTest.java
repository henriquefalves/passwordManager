package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
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

    public static byte[] VALID_HASHKEY;
    public static byte[] INEXISTENT_HASHKEY;
    public static byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);

    public Server server = null;
    public Key key = null;

    public ServerTest() throws NoSuchAlgorithmException {

        byte[] VALID_DOMAIN = "a.b".getBytes(StandardCharsets.UTF_8);
        byte[] VALID_USERNAME = "name".getBytes(StandardCharsets.UTF_8);
        byte[] hashPreKey = Crypto.concatenateData(new byte[][]{VALID_DOMAIN, VALID_USERNAME});
        VALID_HASHKEY = Crypto.hashData(hashPreKey);

       byte[] INEXISTENT_DOMAIN = "d.e".getBytes(StandardCharsets.UTF_8);
         byte[] INEXISTENT_USERNAME = "eman".getBytes(StandardCharsets.UTF_8);
        byte[] invalidHashPreKey = Crypto.concatenateData(new byte[][]{INEXISTENT_DOMAIN, INEXISTENT_USERNAME});
        INEXISTENT_HASHKEY = Crypto.hashData(invalidHashPreKey);




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
        server.put(key, VALID_HASHKEY, PASSWORD);
    }

//    @Test
//    public void GetCorrectExecution() {
//        byte[] pass;
//        try {
//            pass = server.get(key, VALID_HASHKEY);
//            assertTrue(new String(pass, StandardCharsets.UTF_8).equals(new String(PASSWORD, StandardCharsets.UTF_8)));
//        } catch (Exception e) {
//            fail();
//            e.printStackTrace();
//        }
//    }
//
//    @Test(expected = InvalidArgumentsException.class)
//    public void GetInvalidPublicKey() throws RemoteException {
//        server.get(null, VALID_HASHKEY);
//    }
//
//    @Test(expected = InvalidArgumentsException.class)
//    public void GetInvalidHashKey() throws RemoteException {
//        server.get(key, null);
//    }
//
//    @Test(expected = InvalidArgumentsException.class)
//    public void GetInexistentHashKey() throws RemoteException {
//        server.get(key, INEXISTENT_HASHKEY);
//    }

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

//    @Test
//    public void PutCorrectExecutionUpdate() {
//        byte[] serverPass;
//        try {
//            String insertedPassword = "password2";
//            byte[] newPass = insertedPassword.getBytes(StandardCharsets.UTF_8);
//
//            server.put(key,VALID_HASHKEY, newPass);
//            serverPass = server.get(key, VALID_HASHKEY);
//            String fromServer = new String(serverPass, StandardCharsets.UTF_8);
//            assertTrue(fromServer.equals(new String(newPass, StandardCharsets.UTF_8)));
//        } catch (Exception e) {
//            fail();
//            e.printStackTrace();
//        }
//    }

    @Test(expected = InvalidArgumentsException.class)
    public void PutInvalidPublicKey() throws RemoteException {
        server.put(null, VALID_HASHKEY, PASSWORD);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void PutInvalidHashKey() throws RemoteException {
        server.put(key, null, PASSWORD);
    }




}