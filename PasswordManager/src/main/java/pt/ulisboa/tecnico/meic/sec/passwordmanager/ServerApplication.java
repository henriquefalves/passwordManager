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

    private static final int timeAliveByzantineServer= 10000;
    /**
     * 0 - Nada
     * 1 - Crash
     * 2 - Random Writing
     *
     */
    static int BYZANTINE_CODE;
    public static void main(String[] args) {

        int registryPort = Integer.parseInt(args[0]);
        BYZANTINE_CODE =  Integer.parseInt(args[1]);

        try {
            KeyPair keyPair = loadKeys("server.jks", "server123", "server", "123456");
            PrivateKey myPrivateKey = keyPair.getPrivate();
            PublicKey myPublicKey = keyPair.getPublic();
            ServerFrontEnd passwordManager = new ServerFrontEnd(myPrivateKey, myPublicKey);
            passwordManager.setPort(registryPort);
            Registry reg = LocateRegistry.createRegistry(registryPort);
            reg.rebind("password-manager", passwordManager);
            System.out.println("Server Running on Port:" +registryPort);
            if(BYZANTINE_CODE==1) {
                Thread threadKiller = new Thread() {
                    public void run() {
                        try {
                            Thread.sleep(timeAliveByzantineServer);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        System.exit(0);
                    }

                };
                threadKiller.start();
            }

            Scanner reader = new Scanner(System.in);
            boolean on=true;
            while(on) {
                System.out.println("Execute command:");
                System.out.println("exit");
                String choice = reader.nextLine();

                switch (choice) {
                    case "exit":
                        on = false;
                        break;


                    default:
                        System.out.println("Incorrect Command");
                        break;


                }
            }
            } catch (AccessException e) {
            e.printStackTrace();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }


    public static KeyPair loadKeys(String keystoreName, String keystorePass, String alias, String privatePassword){
        KeyPair keyPair = null;
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        FileInputStream fis=null;

        try {
            fis = new FileInputStream(keystoreName);
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        }
        try {
            ks.load(fis, keystorePass.toCharArray());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally{
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        Key key = null;
        try {
            key = ks.getKey(alias, privatePassword.toCharArray());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            java.security.cert.Certificate cert = null;
            try {
                cert = ks.getCertificate(alias);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            PublicKey publicKey = cert.getPublicKey();
            keyPair = new KeyPair(publicKey, (PrivateKey) key);
        }
        return keyPair;
    }

}
