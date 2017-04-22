package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.*;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class ClientFrontEnd implements ServerAPI {
    public static final int TIMEOUT = 5;
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
        rid = 0;
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey) {
        sessionKey = Crypto.generateSessionKey();
        CommunicationLink.initCommunicationLink(myPrivateKey, myPublicKey, serverPublicKey, sessionKey);
    }

    public void register(Key publicKey) throws RemoteException {
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        CommunicationLink.Register registerLink = new CommunicationLink.Register();
        for (int i = 0; i < listReplicas.size(); i++) {

           // Message insecureMessage = new Message(null, null,  null, null, null, null);
            registerLink.initializeRegister(listReplicas.get(i), count);
            Thread thread = new Thread(registerLink);
            thread.start();
        }
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("register: success");
            }
            else {
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

    }

    public void put(Key publicKey, byte[] hashDomainUsername, byte[] password) throws RemoteException {
        wts++;
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        CommunicationLink.Put putLink = new CommunicationLink.Put();
        for (int i = 0; i < listReplicas.size(); i++) {
//            Message insecureMessage = new Message(null, hashKey, password, Crypto.intToByteArray(wts), null, null);
            UserData userDataToSend = new UserData(hashDomainUsername, password, Crypto.intToByteArray(wts));
            Message insecureMessage = new Message(userDataToSend);
            putLink.initializePut(listReplicas.get(i), insecureMessage, count);
            Thread thread = new Thread(putLink);
            thread.start();
        }

        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("put: success");
            }
            else {
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

    }

    public byte[] get(Key publicKey, byte[] hashDomainUsername) throws RemoteException {
        //Regular Register Read Version (1,N)
        rid++;

        List<Message> readList = Collections.synchronizedList(new ArrayList<Message>());
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        CommunicationLink.Get getLink = new CommunicationLink.Get();
        for (int i = 0; i < listReplicas.size(); i++) {

//            Message insecureMessage = new Message(null, hashKey, null, null,Crypto.intToByteArray(rid) , null);
            UserData userDataToSend = new UserData(hashDomainUsername, Crypto.intToByteArray(rid));
            Message insecureMessage = new Message(userDataToSend);
            getLink.initializeGet(listReplicas.get(i), insecureMessage, rid, count, readList);
            Thread thread = new Thread(getLink);
            thread.start();
        }
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("get: success");
                // transform to ArrayList
                ArrayList<Message> resultList = new ArrayList<>();

                // must be synchronized to avoid conflicts
                synchronized (readList) {
                    for(Message m : readList){
                        resultList.add(m);
                    }
                }

                byte[] highestValue = getHighest(resultList);
                return highestValue;
            }
            else {
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

        return null;
    }

    private boolean verifyPasswordValidity(UserData userData) {
        //TODO
        return false;
    }

    private byte[] getHighest(ArrayList<Message> listOfMessages) {
        byte[] highestPassword = listOfMessages.get(0).userData.password;
        byte[] highestTimestamp = listOfMessages.get(0).userData.rid;
        for (Message m : listOfMessages) {
            if (Crypto.byteArrayToInt(m.userData.rid) > Crypto.byteArrayToInt(highestTimestamp)) {
                highestTimestamp = m.userData.rid;
                highestPassword = m.userData.password;
            }
        }
        return highestPassword;
    }

//
//    /**
//     * @param listOfMessages received by the Thread
//     * @return most common password in messages
//     */
//    private byte[] getCommonPasswordValue(ArrayList<Message> listOfMessages) {
//        HashMap<byte[], Integer> map = new HashMap<>();
//        for (Message m : listOfMessages) {
//            Integer val = map.get(m.password);
//            if (val != null) {
//                map.put(m.password, val + 1);
//            } else {
//                map.put(m.password, 1);
//            }
//        }
//        byte[] password = Collections.max(map.entrySet(), Map.Entry.comparingByValue()).getKey();
//        System.out.println("Pass from most common values: " + password);
//        return password;
//    }

}