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
        sessionKey = Crypto.generateSessionKey();
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
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.register(secureMessage);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        byte[] passwordIv = Crypto.generateIv();        // TODO Henrique

        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("PUT-seqNum = " + sequencenumber);
        Message insecureMessage = new Message(sequencenumber, domain, username, password);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, passwordIv, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.put(secureMessage);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        if(this.sequencenumber == null){
            this.sequencenumber = this.getCurrentSeqNum(publicKey);
        }

        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++
        System.out.println("GET-seqNum = " + sequencenumber);
        Message insecureMessage = new Message(sequencenumber, domain, username, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response=  passwordmanager.get(secureMessage);

        boolean[] argsToGet = new boolean[] {false, false, true, false, false};
        byte[][] result = Crypto.checkMessage(response, sequencenumber, argsToGet, null, this.myPrivateKey, this.myPublicKey);
        sequencenumber = sequencenumber.add(BigInteger.ONE);     // seqNum++

        return result[2];
    }

    private BigInteger getCurrentSeqNum(Key publicKey) throws RemoteException {

        Message insecureMessage = new Message(null, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response = passwordmanager.getSequenceNumber(secureMessage);

        boolean[] argsToGet = new boolean[] {false, false, false, false, true};
        byte[][] result = Crypto.checkMessage(response, null, argsToGet, null, this.myPrivateKey, this.myPublicKey);
        BigInteger currSeqNum = new BigInteger(result[4]);
        System.out.println("ClientCrypto-getCurrentSeqNum = " + currSeqNum);
        return currSeqNum;
    }

}
