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
    private byte[] rank;
    ArrayList<CommunicationAPI> listReplicas = new ArrayList<>();
    private int wts;
    private List<Message> readList = Collections.synchronizedList(new ArrayList<Message>());


    public ClientFrontEnd(String rank, ArrayList<String> remoteServerNames) throws RemoteException, NotBoundException, MalformedURLException {
        for (String i : remoteServerNames) {
            CommunicationAPI lookup = (CommunicationAPI) Naming.lookup(i);
            listReplicas.add(lookup);
        }
        rid = 0;
        wts = 0;
        this.rank = Crypto.intToByteArray(Integer.parseInt(rank));
    }

    public void init(Key myPrivateKey, Key myPublicKey, Key serverPublicKey) {
        sessionKey = Crypto.generateSessionKey();
        CommunicationLink.initCommunicationLink(myPrivateKey, myPublicKey, serverPublicKey, sessionKey);
    }

    public void register(Key publicKey) throws RemoteException {
        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        for (int i = 0; i < listReplicas.size(); i++) {
            CommunicationLink.Register registerLink = new CommunicationLink.Register(listReplicas.get(i), count);
            System.out.println("register:"+listReplicas.get(i));
            Thread thread = new Thread(registerLink);
            thread.start();

        }
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("register: success");
            }
            else {
                System.out.println("register: TIMEOUT - Unable to Register.");
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

    }

    public void put(Key publicKey, byte[] hashDomainUsername, byte[] password) throws RemoteException {
        rid++;
        readList = Collections.synchronizedList(new ArrayList<Message>());  // clear readList

        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        readBroadcast(count, hashDomainUsername);
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("put-read-step(1): success");
                // transform to ArrayList
                ArrayList<Message> resultList = new ArrayList<>();
                // must be synchronized to avoid conflicts
                synchronized (readList) {
                    for(Message m : readList){
                        resultList.add(m);
                    }
                }
                HighestInfo highest = getHighest(resultList);
                wts = Crypto.byteArrayToInt(highest.highestTimestamp) + 1;

                count = new CountDownLatch(listReplicas.size()/2 + 1);
                writeBroadcast(count, hashDomainUsername, password,
                                    Crypto.intToByteArray(wts), Crypto.intToByteArray(rid), rank);

                try {
                    if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                        System.out.println("put-write-step(2): success");
                        return;
                    }
                    else {
                        System.out.println("put-write-step(2): TIMEOUT");
                        // TODO
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    // TODO
                }
            }
            else {
                System.out.println("put-read-step(1): TIMEOUT");
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }
    }

    public byte[] get(Key publicKey, byte[] hashDomainUsername) throws RemoteException {
        rid++;
        readList = Collections.synchronizedList(new ArrayList<Message>());  // clear readList

        CountDownLatch count = new CountDownLatch(listReplicas.size()/2 + 1);
        readBroadcast(count, hashDomainUsername);
        try {
            if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                System.out.println("get-read-step(1): success");
                // transform to ArrayList
                ArrayList<Message> resultList = new ArrayList<>();

                // must be synchronized to avoid conflicts
                synchronized (readList) {
                    for(Message m : readList){
                        resultList.add(m);
                    }
                }

                HighestInfo highest = getHighest(resultList);

                count = new CountDownLatch(listReplicas.size()/2 + 1);
                writeBroadcast(count, hashDomainUsername, highest.highestPassword, highest.highestTimestamp,
                        Crypto.intToByteArray(rid), highest.highestRank);

                try {
                    if(count.await(TIMEOUT, TimeUnit.SECONDS)){
                        System.out.println("get-write-step(2): success");
                        return highest.highestPassword;
                    }
                    else {
                        System.out.println("get-write-step(2): TIMEOUT");
                        // TODO
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    // TODO
                }
            }
            else {
                System.out.println("get-read-step(1): TIMEOUT");
                // TODO
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
            // TODO
        }

        return null;
    }

    private void readBroadcast(CountDownLatch count, byte[] hashDomainUsername){

        for (int i = 0; i < listReplicas.size(); i++) {
            UserData userDataToSend = new UserData(hashDomainUsername, Crypto.intToByteArray(rid));
            Message insecureMessage = new Message(null, userDataToSend);
            CommunicationLink.Read readLink = new CommunicationLink.Read(listReplicas.get(i), insecureMessage, rid, count, readList);

            Thread thread = new Thread(readLink);
            thread.start();
        }
    }

    private void writeBroadcast(CountDownLatch count, byte[] hashDomainUsername, byte[] password, byte[] wts, byte[] rid, byte[] rank){
        for (int i = 0; i < listReplicas.size(); i++) {
            UserData userDataToSend = new UserData(hashDomainUsername, password, wts, rid, rank);
            Message insecureMessage = new Message(null, userDataToSend);
            CommunicationLink.Write writeLink = new CommunicationLink.Write(listReplicas.get(i), insecureMessage, Crypto.byteArrayToInt(rid), count);

            Thread thread = new Thread(writeLink);
            thread.start();
        }
    }

    private HighestInfo getHighest(ArrayList<Message> listOfMessages) {
        HighestInfo highest = new HighestInfo();
        highest.highestPassword = listOfMessages.get(0).userData.password;
        highest.highestTimestamp = listOfMessages.get(0).userData.wts;
        highest.highestRank = listOfMessages.get(0).userData.rank;
        for (Message m : listOfMessages) {
            if (Crypto.byteArrayToInt(m.userData.wts) > Crypto.byteArrayToInt(highest.highestTimestamp)) {
                highest.highestTimestamp = m.userData.wts;
                highest.highestPassword = m.userData.password;
                highest.highestRank = m.userData.rank;
            }
            if (Crypto.byteArrayToInt(m.userData.wts) == Crypto.byteArrayToInt(highest.highestTimestamp)) {
                if(Crypto.byteArrayToInt(m.userData.rank) > Crypto.byteArrayToInt(highest.highestRank)){
                    highest.highestPassword = m.userData.password;
                    highest.highestRank = m.userData.rank;
                }
            }
        }
        return highest;
    }

    private class HighestInfo{
        public byte[] highestPassword;
        public byte[] highestTimestamp;
        public byte[] highestRank;
        public HighestInfo(){

        }
    }

}