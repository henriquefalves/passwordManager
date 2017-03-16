package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;

public class ClientCrypto implements ServerAPI {
    private Key myPrivateKey;
    private Key myPublicKey;
    private Key serverPublicKey;
    private byte[] sessionKey;

    CommunicationAPI passwordmanager;

    public ClientCrypto(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = new ClientFrontEnd(remoteServerName);
        sessionKey = null;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }


    public void register(Key publicKey, int sequenceNumber) throws RemoteException {

        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();      // TODO if in all methods
        }
        byte[][] args = new byte[][] {null, null, null };
        Message m = Crypto.getSecureMessage(args, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.register(m);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, int sequenceNumber) throws RemoteException {
        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();
        }
        byte[][] args = new byte[][] {domain, username, password };
        Message m = Crypto.getSecureMessage(args, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.put(m);

    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username, int sequenceNumber) throws RemoteException {
        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();
        }
        byte[][] args = new byte[][] {domain, username, null };
        Message m = Crypto.getSecureMessage(args, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response=  passwordmanager.get(m);

        boolean[] argsToGet = new boolean[] {false, false, true};
        byte[][] result = Crypto.checkMessage(response, argsToGet, null, this.myPrivateKey, this.myPublicKey);
        System.out.println("Client-get: password = " + new String(result[2], StandardCharsets.UTF_8));

        return result[2];
    }

    public int getSequenceNumber(Key publicKey) throws RemoteException, InvalidArgumentsException {
        passwordmanager.getSequenceNumber(new Message());

        return 0;
    }
}
