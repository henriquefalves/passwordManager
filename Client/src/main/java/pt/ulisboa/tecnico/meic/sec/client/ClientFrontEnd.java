package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.WrongChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.*;

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

    //TODO: CHANGE ALL INVOCATIONS ON SERVER (ONLY CALLING 1 RIGHT NOW)

    ArrayList<CommunicationAPI> listReplicas = new ArrayList<>();
    private int acks;
    private int wts;

    public ClientFrontEnd(ArrayList<String> remoteServerNames) throws RemoteException, NotBoundException, MalformedURLException {
        for (String i : remoteServerNames) {
            CommunicationAPI lookup = (CommunicationAPI) Naming.lookup(i);
            listReplicas.add(lookup);
        }
        sessionKey = Crypto.generateSessionKey();

        rid = 0;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey) {
        this.myPrivateKey = myPrivateKey;
        this.myPublicKey = myPublicKey;
        this.serverPublicKey = serverPublicKey;
    }

    public void register(Key publicKey) throws RemoteException {
        for (int i = 0; i < listReplicas.size(); i++) {
            //TODO Execute Thread

            byte[] challenge = this.getChallenge(i);
            Message insecureMessage = new Message(challenge, null, null, null, null, null, null);
            Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

            listReplicas.get(i).register(secureMessage);

        }
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        wts++;
        acks = 0;
        for (int i = 0; i < listReplicas.size(); i++) {
            //TODO Must be multiThreaded
            byte[] challenge = this.getChallenge(i);
            Message insecureMessage = new Message(challenge, domain, username, password, Crypto.leIntToByteArray(wts), null, null);
            Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);
            listReplicas.get(i).put(secureMessage);

            acks++;
            if(acks>listReplicas.size()/2) {
                acks = 0;
                return;
            }

        }


        acks = 0;


    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        //Regular Register Read Version (1,N)
        rid++;
        ArrayList<Message> readList = new ArrayList<>();

        for (int i = 0; i < listReplicas.size(); i++) {

            //Create messages
            byte[] challenge = this.getChallenge(i);
            Message insecureMessage = new Message(challenge, domain, username, null, null,Crypto.leIntToByteArray(rid) , null);
            Message secureMessage = Crypto.getSecureMessage(insecureMessage, this.sessionKey, this.myPrivateKey, this.myPublicKey, this.serverPublicKey);

            //TODO: should be threaded
            //Server call
            Message response = listReplicas.get(i).get(secureMessage);
            Message result = Crypto.checkMessage(response, this.myPrivateKey, this.myPublicKey);
            checkChallenge(challenge, result.challenge);

            //TODO: check signature from UserData - FOR NOW this is still not working
            //  because get should return UserData and not byte[] password
            //verifyPasswordValidity(result.userData);

            System.out.println("Message rid: " + result.rid + ". Local rid: " + rid);
            //bonrr (algorithm) makes this check
            if (Crypto.byteArrayToLeInt(result.rid) == rid) {
                //Add result to read list
                readList.add(result);
                if (readList.size() > (listReplicas.size() / 2)) {
                    byte[] commonValue = getCommonPasswordValue(readList);
                    return commonValue;
                }
            }
        }
        return null;
    }

    private boolean verifyPasswordValidity(UserData userData) {
        //TODO
        return false;
    }


    /**
     * @param listOfMessages received by the Thread
     * @return most common password in messages
     */
    private byte[] getCommonPasswordValue(ArrayList<Message> listOfMessages) {
        HashMap<byte[], Integer> map = new HashMap<>();
        for (Message m : listOfMessages) {
            Integer val = map.get(m.password);
            if (val != null) {
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
        if (receivedChallenge == null || !Arrays.equals(expectedChallenge, receivedChallenge)) {
            System.out.println("Client-FE-checkChallenge: Invalid challenge");
            throw new WrongChallengeException();
            //TODO handle exception
        }
    }
}