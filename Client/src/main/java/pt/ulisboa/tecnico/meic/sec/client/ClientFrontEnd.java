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
import java.util.*;

public class ClientFrontEnd implements ServerAPI {
    private Key myPrivateKey;
    private Key myPublicKey;
    private Key serverPublicKey;
    private byte[] sessionKey;
    private int rid;
    private ArrayList<Message> readList;
    private int serverCount;
    private int FAKE_WTS = 0;

    //TODO: CHANGE ALL INVOCATIONS ON SERVER (ONLY CALLING 1 RIGHT NOW)

    //TODO: turn this into arraylist
    ArrayList<CommunicationAPI> passwordmanagers = new ArrayList<>();

    public ClientFrontEnd(ArrayList<String> remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        //passwordmanager = (CommunicationAPI) Naming.lookup(remoteServerName);
        sessionKey = Crypto.generateSessionKey();

        rid = 0;
        readList = new ArrayList<>();
        serverCount = remoteServerName.size();
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }

    public void register(Key publicKey) throws RemoteException {
        byte[] challenge = this.getChallenge();
        Message insecureMessage = new Message(challenge, null, null, null, FAKE_WTS, 0, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanagers.get(0).register(secureMessage);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        byte[] challenge = this.getChallenge();
        Message insecureMessage = new Message(challenge, domain, username, password, FAKE_WTS, 0, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        passwordmanagers.get(0).put(secureMessage);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        //Regular Register Read Version (1,N)
        rid++;
        readList = new ArrayList<>();
        //Now send message to all servers

        byte[] challenge = this.getChallenge();
        //need to add RID here
        Message insecureMessage = new Message(challenge, domain, username, null, FAKE_WTS, rid, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

        for(int i = 0; i < serverCount; i++) {
            //TODO: should be threaded
            Message response = passwordmanagers.get(i).get(secureMessage);
            Message result = Crypto.checkMessage(response, this.myPrivateKey, this.myPublicKey);
            checkChallenge(challenge, result.challenge);
            readList.add(result);
            if(readList.size() > (serverCount/2)) {
                byte[] commonValue = getCommonPasswordValue(readList);
                readList = new ArrayList<>();
                return commonValue;
            }
        }
        return null;
    }

    public byte[] getCommonPasswordValue(ArrayList<Message> messages) {
        HashMap<byte[], Integer> map = new HashMap<>();
        for(Message m : messages) {
            Integer val = map.get(m.password);
            if(val != null) {
                map.put(m.password, val + 1);
            } else {
                map.put(m.password, 1);
            }
        }
        byte[] password = Collections.max(map.entrySet(), Map.Entry.comparingByValue()).getKey();
        System.out.println("Pass from most common values: " + password);
        return password;
    }

    private byte[] getChallenge() throws RemoteException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response = passwordmanagers.get(0).getChallenge(secureMessage);

        Message result = Crypto.checkMessage(response, this.myPrivateKey, this.myPublicKey);
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