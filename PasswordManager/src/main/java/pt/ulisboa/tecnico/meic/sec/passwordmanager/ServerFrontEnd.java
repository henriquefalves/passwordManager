package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    public ServerCrypto server;

    protected ServerFrontEnd() throws RemoteException {
        server = new ServerCrypto();
    }

    public void register(Message message) throws RemoteException {
    // server.server.clientPublicKey

        byte[] secretKey = Crypto.decrypt(message.secretKey, server.server.myPrivateKey);
        System.out.println("Server: secret key: " + new String(secretKey, StandardCharsets.UTF_8));

        byte[] decipheredDomain = Crypto.decipherSymmetric(secretKey, message.randomIv, message.domain);
        System.out.println("Server: domain = " + new String(decipheredDomain, StandardCharsets.UTF_8));

        byte[] decipheredUsername = Crypto.decipherSymmetric(secretKey, message.randomIv, message.username);
        System.out.println("Server: username = " + new String(decipheredUsername, StandardCharsets.UTF_8));

        byte[] decipheredPassword = Crypto.decipherSymmetric(secretKey, message.randomIv, message.password);
        System.out.println("Server: password = " + new String(decipheredPassword, StandardCharsets.UTF_8));

        byte[] signedData = Crypto.decipherSymmetric(secretKey, message.randomIv, message.signature);
        System.out.println("Server: signedData = " + new String(signedData, StandardCharsets.UTF_8));

        byte[] dataToHash = Crypto.createData(new byte[][] {message.randomIv, decipheredDomain, decipheredUsername, decipheredPassword, message.publicKey.getEncoded(), server.server.myPublicKey.getEncoded() });
        byte[] digestToCheckSign = Crypto.hashData(dataToHash);

        boolean integrity = Crypto.verifySign((PublicKey) message.publicKey, digestToCheckSign, signedData);
        if (!integrity){
            System.out.println("Server: Invalid signature");
            return;
            // TODO exception?
        }
        server.register(message.publicKey);
    }

    public void put(Message message) throws RemoteException {
        //TODO: cenas

        //server.put(publicKey, domain, username, password);
    }

    public byte[] get(Message message) throws RemoteException {
        //TODO: cenas


        //byte[] password = server.get(publicKey, domain, username);

        //TODO: mais cenas e retorna isso
        return "string".getBytes(StandardCharsets.UTF_8);    }
}
