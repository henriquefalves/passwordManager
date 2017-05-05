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
    public static byte[] VALID_PASSWORD = "Primeira".getBytes(StandardCharsets.UTF_8);
    public static byte[] VALID_PASSWORD2 = "SegundaPassword".getBytes(StandardCharsets.UTF_8);
    public static int faults=0;
    public static int numberServers=0;
    public static int numberClients=0;
    public  int initialPort=8006;

    @Test
    public void TestN() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();
            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            byte[] retrievedPassword = listClients.get(0).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            fail();

        }
    }

    @Test
    public void Test2() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();
            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            byte[] retrievedPassword = listClients.get(0).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD2);
            retrievedPassword = listClients.get(0).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD2, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void Test4() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(1).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();


            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            byte[] retrievedPassword = listClients.get(1).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
        } catch (Exception e) {

            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void Test5() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(1).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();
            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            listClients.get(1).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD2);

            byte[] retrievedPassword = listClients.get(0).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD2, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
        } catch (Exception e) {

            e.printStackTrace();
            fail();
        }
    }
    @Test
    public void Test6() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(1).init(ks, keystoreName, keystorePassword);
            listClients.get(2).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();

            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            byte[] retrievedPassword = listClients.get(1).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));

            listClients.get(1).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD2);
            retrievedPassword = listClients.get(2).retrieve_password(VALID_DOMAIN, VALID_USERNAME);

            Assert.assertEquals(new String(VALID_PASSWORD2, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }
    @Test
    public void Test13() {
        try {
            faults=Integer.valueOf(System.getProperty("faults"));
            numberServers=Integer.valueOf(System.getProperty("numberServers"));
            numberClients=Integer.valueOf(System.getProperty("numberClients"));



            ArrayList<String> listOfReplicas = new ArrayList<String>();
            for(int i = 0; i <numberServers ;i++,initialPort++){
                String replica = "rmi://localhost:" + initialPort + "/password-manager";
                System.out.println(replica);
                listOfReplicas.add(replica);

            }
            ArrayList<Client> listClients = new ArrayList<Client>();

            for(int i = 1; i <numberClients+1 ;i++,initialPort++) {
                listClients.add(new Client(new Integer(i).toString(), listOfReplicas, faults));

            }
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
            } catch (KeyStoreException e) {
                System.out.println("Unable to create Keystore");
            }

            String keystoreName = "henriqueKeyStore.jks";
            String keystorePassword = "henrique123";
            listClients.get(0).init(ks, keystoreName, keystorePassword);
            listClients.get(1).init(ks, keystoreName, keystorePassword);
            listClients.get(2).init(ks, keystoreName, keystorePassword);
            listClients.get(0).register_user();

            listClients.get(0).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);
            listClients.get(1).save_password(VALID_DOMAIN, VALID_USERNAME, VALID_PASSWORD);

            byte[] retrievedPassword = listClients.get(2).retrieve_password(VALID_DOMAIN, VALID_USERNAME);
            Assert.assertEquals(new String(VALID_PASSWORD, StandardCharsets.UTF_8),new String(retrievedPassword, StandardCharsets.UTF_8));

        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }


}
