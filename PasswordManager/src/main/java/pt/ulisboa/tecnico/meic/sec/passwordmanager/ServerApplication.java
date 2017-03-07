package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.*;


public class ServerApplication {

    public static void main(String[] args) {

        System.out.println("SUCCESS SERVER");

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
            Server s = new Server();
            s.register(kPub);
            s.register(kPub);
            s.put(kPub, domain, username, password);
            s.put(kPriv, domain, username, password);
            String st = new String( s.get(kPub, "domain".getBytes(), "username".getBytes()), StandardCharsets.UTF_8);
            System.out.println("Result of get: " + st);

        } catch (RemoteException e) {
            e.printStackTrace();
        }

    }
}
