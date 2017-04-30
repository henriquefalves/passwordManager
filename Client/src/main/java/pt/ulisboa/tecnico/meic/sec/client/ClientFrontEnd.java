package pt.ulisboa.tecnico.meic.sec.client;

import javafx.util.Pair;
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
    private boolean reading;

    //TODO: CHANGE ALL INVOCATIONS ON SERVER (ONLY CALLING 1 RIGHT NOW)

    ArrayList<CommunicationAPI> listReplicas = new ArrayList<>();
    private int wts;

    private List<Message> readList = Collections.synchronizedList(new ArrayList<Message>());

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
            registerLink.initializeRegister(listReplicas.get(i), count);
            Thread thread = new Thread(registerLink);
            thread.start();
        }
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("register: success");
            }
            else {
                System.out.println("register: TIMEOUT");
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

    }

    public void put(Key publicKey, byte[] hashDomainUsername, byte[] password) throws RemoteException {
        wts++;
        rid++;
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        CommunicationLink.Put putLink = new CommunicationLink.Put();
        for (int i = 0; i < listReplicas.size(); i++) {
            UserData userDataToSend = new UserData(hashDomainUsername, password, Crypto.intToByteArray(wts), Crypto.intToByteArray(rid));
            Message insecureMessage = new Message(null, userDataToSend);
            putLink.initializePut(listReplicas.get(i), insecureMessage, rid, count);

            Thread thread = new Thread(putLink);
            thread.start();
        }

        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                if (reading) {
                    reading = false;
                }
                System.out.println("put: success");
            }
            else {
                System.out.println("put: TIMEOUT");
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
        reading = true;
        readList = Collections.synchronizedList(new ArrayList<Message>());  // clear readList
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        CommunicationLink.Get getLink = new CommunicationLink.Get();
        for (int i = 0; i < listReplicas.size(); i++) {

            UserData userDataToSend = new UserData(hashDomainUsername, Crypto.intToByteArray(rid));
            Message insecureMessage = new Message(null, userDataToSend);
            getLink.initializeGet(listReplicas.get(i), insecureMessage, rid, count, readList);
            Thread thread = new Thread(getLink);
            thread.start();
        }
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                // transform to ArrayList
                ArrayList<Message> resultList = new ArrayList<>();

                // must be synchronized to avoid conflicts
                synchronized (readList) {
                    for(Message m : readList){
                        resultList.add(m);
                    }
                }

                byte[] highestTimestamp = getHighest(resultList).getKey();
                byte[] highestValue = getHighest(resultList).getValue();
                System.out.println("get: success");

                rid--;
                // wts--;
                wts = Crypto.byteArrayToInt(highestTimestamp) - 1;
                put(publicKey, hashDomainUsername, highestValue);

                return highestValue;
            }
            else {
                System.out.println("get: TIMEOUT");
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

        return null;
    }

    private Pair<byte[], byte[]> getHighest(ArrayList<Message> listOfMessages) {
        byte[] highestPassword = listOfMessages.get(0).userData.password;
        byte[] highestTimestamp = listOfMessages.get(0).userData.wts;
        for (Message m : listOfMessages) {
            if (Crypto.byteArrayToInt(m.userData.wts) > Crypto.byteArrayToInt(highestTimestamp)) {
                highestTimestamp = m.userData.wts;
                highestPassword = m.userData.password;
            }
        }
        return new Pair<byte[], byte[]>(highestTimestamp, highestPassword);
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