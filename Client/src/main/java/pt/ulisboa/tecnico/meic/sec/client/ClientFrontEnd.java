package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.WrongChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.Arrays;

public class ClientFrontEnd implements ServerAPI {
    private Key myPrivateKey;
    private Key myPublicKey;
    private Key serverPublicKey;
    private byte[] sessionKey;
    private boolean sendSessionKey;

    CommunicationAPI passwordmanager;

    public ClientFrontEnd(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = (CommunicationAPI) Naming.lookup(remoteServerName);
        sessionKey = Crypto.generateSessionKey();
        sendSessionKey = true;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }


    public void register(Key publicKey) throws RemoteException {
        byte[] challenge = this.getChallenge();

        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.register(secureMessage);
        this.sendSessionKey = false;
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        byte[] challenge = this.getChallenge();
        Message insecureMessage = new Message(challenge, domain, username, password);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanager.put(secureMessage);
        this.sendSessionKey = false;
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        byte[] challenge = this.getChallenge();
        Message insecureMessage = new Message(challenge, domain, username, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response =  passwordmanager.get(secureMessage);
        this.sendSessionKey = false;

        Message result = Crypto.checkMessage(response, sessionKey, this.myPrivateKey, this.myPublicKey);
        checkChallenge(challenge, result.challenge);
        return result.password;
    }

    private byte[] getChallenge() throws RemoteException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, sendSessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response = passwordmanager.getChallenge(secureMessage);
        this.sendSessionKey = false;

        Message result = Crypto.checkMessage(response, sessionKey, this.myPrivateKey, this.myPublicKey);
        return result.challenge;
    }

    private void checkChallenge(byte[] expectedChallenge, byte[] receivedChallenge) {
        if(receivedChallenge == null || !Arrays.equals(expectedChallenge, receivedChallenge)){
            System.out.println("Client-FE-checkChallenge: Invalid challenge");
            throw new WrongChallengeException();
            //TODO handle exception
        }
    }
}