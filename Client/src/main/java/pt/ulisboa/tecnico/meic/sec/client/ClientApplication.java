package pt.ulisboa.tecnico.meic.sec.client;


import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Scanner;
import java.security.*;


public class ClientApplication {
    public static void main(String[] args) {

        try {
            ServerAPI server = (ServerAPI) Naming.lookup("rmi://localhost:8006/password-manager");
            Client client = new Client(server);

            Key kPub = null;
            Key kPriv = null;
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                keyGen.initialize(1024, random);
                KeyPair pair = keyGen.generateKeyPair();
                PrivateKey priv = pair.getPrivate();
                PublicKey pub = pair.getPublic();
                kPub = pub;
                kPriv = priv;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }

            try {
                byte[] domain = "domain".getBytes(StandardCharsets.UTF_8);
                byte[] username = "username".getBytes(StandardCharsets.UTF_8);
                byte[] password = "password".getBytes(StandardCharsets.UTF_8);
                server.register(kPub);
                server.register(kPub);
                server.put(kPub, domain, username, password);
                server.put(kPriv, domain, username, password);
                String st = new String( server.get(kPub, "domain".getBytes(), "username".getBytes()), StandardCharsets.UTF_8);
                System.out.println("Result of get: " + st);

            } catch (RemoteException e) {
                e.printStackTrace();
            }

            System.out.println("Press Enter to exit");
            String button = (new Scanner(System.in)).nextLine();
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

    }
}
