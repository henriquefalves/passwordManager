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
    private boolean sendSessionKey;
    private BigInteger sequencenumber;

    CommunicationAPI passwordmanager;

    public ClientCrypto(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = new ClientFrontEnd(remoteServerName);
        sessionKey = Crypto.generateSessionKey();
        sendSessionKey = true;
        sequencenumber = null;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }


    public void register(Key publicKey) throws RemoteException {
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("REGISTER-seqNum = " + sequencenumber);
        Message insecureMessage = new Message(sequencenumber, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.register(secureMessage);
        this.sendSessionKey = false;
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        byte[] passwordIv = Crypto.generateIv();        // TODO Henrique

        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("PUT-seqNum = " + sequencenumber);
        Message insecureMessage = new Message(sequencenumber, domain, username, password);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, passwordIv, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.put(secureMessage);
        this.sendSessionKey = false;
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }

        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("GET-seqNum = " + sequencenumber);
        Message insecureMessage = new Message(sequencenumber, domain, username, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response =  passwordmanager.get(secureMessage);
        this.sendSessionKey = false;

        Message result = Crypto.checkMessage(response, sequencenumber, sessionKey, this.myPrivateKey, this.myPublicKey);
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++

        return result.password;
    }

    private BigInteger getCurrentSeqNum(Key publicKey) throws RemoteException {

        Message insecureMessage = new Message(null, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response = passwordmanager.getSequenceNumber(secureMessage);
        this.sendSessionKey = false;

        Message result = Crypto.checkMessage(response, null, sessionKey, this.myPrivateKey, this.myPublicKey);
        BigInteger currSeqNum = new BigInteger(result.sequenceNumber);
        System.out.println("ClientCrypto-getCurrentSeqNum = " + currSeqNum);
        return currSeqNum;
    }

}
