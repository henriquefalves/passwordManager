package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.math.BigInteger;
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
    private BigInteger sequencenumber;

    CommunicationAPI passwordmanager;

    public ClientCrypto(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = new ClientFrontEnd(remoteServerName);
        sessionKey = null;
        sequencenumber = null;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }


    public void register(Key publicKey) throws RemoteException {
        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();      // TODO if in all methods
        }
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("REGISTER-seqNum = " + sequencenumber);
        byte[][] args = new byte[][] {sequencenumber.toByteArray(), null, null, null };
        Message m = Crypto.getSecureMessage(args, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.register(m);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        byte[] passwordIv = Crypto.generateIv();        // TODO Henrique
        System.out.println("ClientCrypto-put: passwordId = "+ new String(passwordIv, StandardCharsets.UTF_8));

        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();
        }
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }

        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("PUT-seqNum = " + sequencenumber);
        byte[][] args = new byte[][] {sequencenumber.toByteArray(), domain, username, password };
        Message m = Crypto.getSecureMessage(args, passwordIv, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.put(m);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {


        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();
        }
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }

        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("GET-seqNum = " + sequencenumber);
        byte[][] args = new byte[][] {sequencenumber.toByteArray(), domain, username, null };
        Message m = Crypto.getSecureMessage(args, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response=  passwordmanager.get(m);

        boolean[] argsToGet = new boolean[] {false, false, true, false, false};
        byte[][] result = Crypto.checkMessage(response, sequencenumber, argsToGet, null, this.myPrivateKey, this.myPublicKey);
        System.out.println("Client-get: password = " + new String(result[2], StandardCharsets.UTF_8));
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++

        return result[2];
    }

    private BigInteger getCurrentSeqNum(Key publicKey) throws RemoteException {
        if(this.sessionKey == null){
            this.sessionKey = Crypto.generateSessionKey();
        }

        byte[][] args = new byte[][] {null, null, null, null };
        Message m = Crypto.getSecureMessage(args, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

        Message response = passwordmanager.getSequenceNumber(m);
        boolean[] argsToGet = new boolean[] {false, false, false, false, true};
        byte[][] result = Crypto.checkMessage(response, null, argsToGet, null, this.myPrivateKey, this.myPublicKey);
        BigInteger currSeqNum = new BigInteger(result[4]);
        System.out.println("ClientCrypto-getCurrentSeqNum = " + currSeqNum);
        return currSeqNum;
    }

}
