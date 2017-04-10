package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.WrongChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.net.MalformedURLException;
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
    private int FAKE_WTS = 0;

    //TODO: CHANGE ALL INVOCATIONS ON SERVER (ONLY CALLING 1 RIGHT NOW)

    ArrayList<CommunicationAPI> listReplicas = new ArrayList<>();
    private int acks;
    private int wts;

    public ClientFrontEnd(ArrayList<String> remoteServerNames) throws RemoteException, NotBoundException, MalformedURLException {
       for(String i:remoteServerNames) {
           CommunicationAPI lookup = (CommunicationAPI) Naming.lookup(i);
           listReplicas.add(lookup);
       }
        sessionKey = Crypto.generateSessionKey();

        rid = 0;
        readList = new ArrayList<>();
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey){
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }

    public void register(Key publicKey) throws RemoteException {
        for(int i = 0; i < listReplicas.size(); i++) {

            byte[] challenge = this.getChallenge(i);
            Message insecureMessage = new Message(challenge, null, null, null, FAKE_WTS, 0, null);
            Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

           //TODO Execute Thread
           listReplicas.get(i).register(secureMessage);

       }
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        wts++;
        acks=0;
        for(int i = 0; i < listReplicas.size(); i++) {
            //TODO Must be multiThreaded
            byte[] challenge = this.getChallenge(i);
            Message insecureMessage = new Message(challenge, domain, username, password, FAKE_WTS, 0, null);
            Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
            listReplicas.get(i).put(secureMessage);
            acks++;

        }
        while(acks> listReplicas.size()/2) {
            try {
                Thread.sleep(2000 * listReplicas.size());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        acks=0;


    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        //Regular Register Read Version (1,N)
        rid++;
        readList = new ArrayList<>();
        //Now send message to all servers
        for(int i = 0; i < listReplicas.size(); i++) {

        byte[] challenge = this.getChallenge(i);
        //TODO need to add RID here
        Message insecureMessage = new Message(challenge, domain, username, null, FAKE_WTS, rid, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

            //TODO: should be threaded
            Message response = listReplicas.get(i).get(secureMessage);
            Message result = Crypto.checkMessage(response, this.myPrivateKey, this.myPublicKey);
            checkChallenge(challenge, result.challenge);
            readList.add(result);
            if(readList.size() > (listReplicas.size()/2)) {
                byte[] commonValue = getCommonPasswordValue(readList);
                readList = new ArrayList<>();
                return commonValue;
            }
            //TODO BY Henrique considera isto e diz-me qualquer coisa
//            while(!readList.size() > (listReplicas.size()/2)|| THRESHOLD_WAITTIME){
//                Thread.sleep(2000*listReplicas.size());
//            }
//            byte[] commonValue = getCommonPasswordValue(readList);
//            readList = new ArrayList<>();
//            return commonValue;

        }
        return null;
    }

    private byte[] getCommonPasswordValue(ArrayList<Message> messages) {
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

    private byte[] getChallenge(int replicaID) throws RemoteException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
        Message response = listReplicas.get(replicaID).getChallenge(secureMessage);

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