package pt.ulisboa.tecnico.meic.sec.client;


import pt.ulisboa.tecnico.meic.sec.client.exceptions.WrongChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;

import java.rmi.RemoteException;
import java.security.Key;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class CommunicationLink {
    private static Key myPrivateKey;
    private static Key myPublicKey;
    private static Key serverPublicKey;
    private static byte[] sessionKey;


    public static void initCommunicationLink(Key myPrivate, Key myPublic, Key servPublic, byte[] sessionKey){
        CommunicationLink.myPrivateKey = myPrivate;
        CommunicationLink.myPublicKey = myPublic;
        CommunicationLink.serverPublicKey = servPublic;
        CommunicationLink.sessionKey = sessionKey;
    }

    private static byte[] getChallenge(CommunicationAPI server) throws RemoteException {
        Message insecureMessage = new Message();
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, sessionKey, myPrivateKey, myPublicKey, serverPublicKey);
        Message response = server.getChallenge(secureMessage);

        Message result = Crypto.checkMessage(response, myPrivateKey, myPublicKey);
        return result.challenge;
    }



    public static class Register implements Runnable{
        private CommunicationAPI server;
        CountDownLatch countDown;

        public void initializeRegister(CommunicationAPI server, CountDownLatch count){
            this.server = server;
            this.countDown = count;
        }

        @Override
        public void run() {

            try {
                byte[] challenge = CommunicationLink.getChallenge(this.server);
                Message message = new Message(challenge, null);
                Message secureMessage = Crypto.getSecureMessage(message, sessionKey, myPrivateKey, myPublicKey, serverPublicKey);
                this.server.register(secureMessage);
                this.countDown.countDown();
            } catch (Exception e) {
                e.printStackTrace();
                // TODO listener to catch exceptions in main thread
            }
        }
    }



    public static class Put implements Runnable{
        private CommunicationAPI server;
        Message message;
        CountDownLatch countDown;

        public void initializePut(CommunicationAPI server, Message m, CountDownLatch count){
            this.server = server;
            this.message = m;
            this.countDown = count;
        }

        @Override
        public void run() {

            try {
                byte[] challenge = CommunicationLink.getChallenge(this.server);
                message.challenge = challenge;
                Message secureMessage = Crypto.getSecureMessage(message, sessionKey, myPrivateKey, myPublicKey, serverPublicKey);
                this.server.put(secureMessage);
                this.countDown.countDown();
            } catch (Exception e) {
                e.printStackTrace();
                // TODO listener to catch exceptions in main thread
            }
        }
    }



    public static class Get implements Runnable{
        private CommunicationAPI server;
        private Message message;
        private CountDownLatch countDown;
        private List<Message> sincronizedList;
        private int expectedRid;

        public void initializeGet(CommunicationAPI server, Message m, int rid, CountDownLatch count, List<Message> sincronizedList){
            this.server = server;
            this.message = m;
            this.expectedRid = rid;
            this.countDown = count;
            this.sincronizedList = sincronizedList;
        }

        @Override
        public void run() {
            try {
                byte[] challenge = CommunicationLink.getChallenge(this.server);
                message.challenge = challenge;
                Message secureMessage = Crypto.getSecureMessage(message, sessionKey, myPrivateKey, myPublicKey, serverPublicKey);
                Message response = this.server.get(secureMessage);
                Message result = Crypto.checkMessage(response, myPrivateKey, myPublicKey);
                CommunicationLink.checkChallenge(challenge, result.challenge);
                // TODO check password signature
                if (Crypto.byteArrayToInt(result.userData.rid) == expectedRid){
                    sincronizedList.add(result);
                    this.countDown.countDown();
                }
            } catch (Exception e) {
                e.printStackTrace();
                // TODO listener to catch exceptions in main thread
            }
        }
    }



    private static void checkChallenge(byte[] expectedChallenge, byte[] receivedChallenge) {
        if (receivedChallenge == null || !Arrays.equals(expectedChallenge, receivedChallenge)) {
            System.out.println("Client-FE-checkChallenge: Invalid challenge");
            throw new WrongChallengeException();
            //TODO handle exception
        }
    }


}