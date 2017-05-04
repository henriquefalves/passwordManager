package pt.ulisboa.tecnico.meic.sec.client;


import org.junit.Assert;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.TimeOutException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import static org.junit.Assert.fail;



public class ClientIndependetTests {

    public static byte[] VALID_DOMAIN = "facebook.com".getBytes(StandardCharsets.UTF_8);
    public static byte[] VALID_USERNAME = "joao".getBytes(StandardCharsets.UTF_8);
    public static byte[] VALID_PASSWORD = "passwordSecreta".getBytes(StandardCharsets.UTF_8);
    public static Client client1 = null;

    @Test
    public void Test1() {
        try {
            ArrayList<String> listOfReplicas = new ArrayList<String>();
            listOfReplicas.add("rmi://localhost:8006/password-manager");

            client1 = new Client("1", listOfReplicas);

            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            client1.init(ks, keystoreName, keystorePassword);
            client1.register_user();
            client1.save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            byte[] retrievedPassword = client1.retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(VALID_PASSWORD,retrievedPassword);
        } catch (Exception e) {
            fail();
            e.printStackTrace();
        }
    }

    @Test
    public void Test2() {
        try {
            ArrayList<String> listOfReplicas = new ArrayList<String>();
            listOfReplicas.add("rmi://localhost:8006/password-manager");

            client1 = new Client("1", listOfReplicas);

            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            client1.init(ks, keystoreName, keystorePassword);
            client1.register_user();
            client1.save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
        } catch (Exception e) {
            fail();
            e.printStackTrace();
        }
    }

    @Test
    public void Test7() {
        try {
            ArrayList<String> listOfReplicas = new ArrayList<String>();
            listOfReplicas.add("rmi://localhost:8006/password-manager");
            listOfReplicas.add("rmi://localhost:8007/password-manager");
            listOfReplicas.add("rmi://localhost:8008/password-manager");
            listOfReplicas.add("rmi://localhost:8009/password-manager");


            client1 = new Client("1", listOfReplicas);

            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            client1.init(ks, keystoreName, keystorePassword);
            client1.register_user();
            client1.save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);

        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void SavePasswordSuccess1Client3Server() {
        try {
            ArrayList<String> listOfReplicas = new ArrayList<String>();
            listOfReplicas.add("rmi://localhost:8006/password-manager");
            listOfReplicas.add("rmi://localhost:8007/password-manager");
            listOfReplicas.add("rmi://localhost:8008/password-manager");


            client1 = new Client("1", listOfReplicas);

            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            client1.init(ks, keystoreName, keystorePassword);
            client1.register_user();
            client1.save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
        } catch (Exception e) {
            fail();
            System.out.println(e.getClass().getName());
            e.printStackTrace();
        }
    }

    @Test(expected = TimeOutException.class)
    public void SavePasswordSuccess1Client3Server1Byzantine() {
        try {
            ArrayList<String> listOfReplicas = new ArrayList<String>();
            listOfReplicas.add("rmi://localhost:8006/password-manager");
            listOfReplicas.add("rmi://localhost:8007/password-manager");
            listOfReplicas.add("rmi://localhost:8008/password-manager");


            client1 = new Client("1", listOfReplicas);


            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            client1.init(ks, keystoreName, keystorePassword);
            client1.register_user();
            client1.save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);

        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}
