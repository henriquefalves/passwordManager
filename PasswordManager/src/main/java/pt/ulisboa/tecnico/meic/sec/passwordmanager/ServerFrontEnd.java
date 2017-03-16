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
        boolean[] argsToGet = new boolean[] {false, false, false};
        byte[][] result = Crypto.checkMessage(message, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);

        server.register(message.publicKey, 1);
    }

    public void put(Message message) throws RemoteException {

        boolean[] argsToGet = new boolean[] {true, true, true};
        byte[][] result = Crypto.checkMessage(message, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        System.out.println("Server-put: domain = " + new String(result[0], StandardCharsets.UTF_8));
        System.out.println("Server-put: username = " + new String(result[1], StandardCharsets.UTF_8));
        System.out.println("Server-put: password = " + new String(result[2], StandardCharsets.UTF_8));

        server.put(message.publicKey, result[0], result[1], result[2], 1);
    }

    public Message get(Message message) throws RemoteException {
        boolean[] argsToGet = new boolean[] {true, true, false};
        byte[][] result = Crypto.checkMessage(message, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        System.out.println("Server-get: domain = " + new String(result[0], StandardCharsets.UTF_8));
        System.out.println("Server-get: username = " + new String(result[1], StandardCharsets.UTF_8));
        byte[] password = server.get(message.publicKey, result[0], result[1], 1);


        byte[] sessionKey = Crypto.generateSessionKey();            // FIXME sessionsKey management
        byte[][] args = new byte[][] {null, null, password };
        Message m = Crypto.getSecureMessage(args, sessionKey, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);

        return m;
    }


    // ???
    @Override
    public int getSequenceNumber(Message message) throws RemoteException {
        return 0;
    }
}

