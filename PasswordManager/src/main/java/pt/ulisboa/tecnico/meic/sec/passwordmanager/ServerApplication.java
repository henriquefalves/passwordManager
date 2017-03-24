package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.AccessException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;


public class ServerApplication {
    private static final String KEYSTORENAME= "server.jks";
    private static final String KEYSTOREPASS= "server123";

    private static PrivateKey myPrivateKey;
    private static PublicKey myPublicKey;

    public static void main(String[] args) {

        int registryPort = Integer.parseInt(args[0]);
        try {
            loadKeys();
            ServerFrontEnd passwordManager = new ServerFrontEnd(myPrivateKey, myPublicKey);
            System.out.println("Server created");
            Registry reg = LocateRegistry.createRegistry(registryPort);
            System.out.println("Registry created!!");
            reg.rebind("password-manager", passwordManager);
            System.out.println("Rebind done!!");

            System.out.println("Press Enter to exit");
            String button = (new Scanner(System.in)).nextLine();

        } catch (AccessException e) {
            e.printStackTrace();
        } catch (RemoteException e) {
            e.printStackTrace();
        }

    }

    private static void loadKeys(){

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        FileInputStream fis=null;

        try {
            fis = new FileInputStream(KEYSTORENAME);
        } catch (FileNotFoundException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            ks.load(fis, KEYSTOREPASS.toCharArray());
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        finally{
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }


        Key key = null;
        try {
            key = ks.getKey("server", "123456".toCharArray());
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            java.security.cert.Certificate cert = null;
            try {
                cert = ks.getCertificate("server");
            } catch (KeyStoreException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);		// ???
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();

        }

//        try {
//            clientPublicKey = ks.getCertificate("henrique").getPublicKey();
//        } catch (KeyStoreException e) {
//            System.out.println("Unable to load Public Key From Server");
//            e.printStackTrace();
//        }

    }
}
