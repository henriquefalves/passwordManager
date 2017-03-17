package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    public ServerCrypto server;
    private Map<String, BigInteger> sequenceNumbers;

    protected ServerFrontEnd() throws RemoteException {
        server = new ServerCrypto();
        sequenceNumbers = new HashMap<>();
    }

    public void register(Message message) throws RemoteException {

        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return;
        }

        System.out.println("REGISTER-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {false, false, false, false, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        server.register(message.publicKey);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!
    }

    public void put(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return;
        }

        System.out.println("PUT-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {true, true, true, true, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
//        System.out.println("Server-put: domain = " + new String(result[0], StandardCharsets.UTF_8));
//        System.out.println("Server-put: username = " + new String(result[1], StandardCharsets.UTF_8));
//        System.out.println("Server-put: password = " + new String(result[2], StandardCharsets.UTF_8));
//        System.out.println("Server-put: passwordIV = " + new String(result[3], StandardCharsets.UTF_8));

        // TODO Henrique result[3] is received passwordIv

        server.put(message.publicKey, result[0], result[1], result[2]);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!
    }

    public Message get(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return null;
        }

        System.out.println("GET-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {true, true, false, false, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        byte[] password = server.get(message.publicKey, result[0], result[1]);

        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!


        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!

        byte[] sessionKey = Crypto.generateSessionKey();            // FIXME sessionsKey management
        byte[][] args = new byte[][] {sequenceNumber.toByteArray(), null, null, password };
        // TODO pass passwordIv and check in ClientCrypto
        Message m = Crypto.getSecureMessage(args, null, sessionKey, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);
        return m;
    }


    @Override
    public Message getSequenceNumber(Message message) throws RemoteException {
        boolean[] argsToGet = new boolean[] {false, false, false, false, false};
        byte[][] result = Crypto.checkMessage(message, null, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);

        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        BigInteger sequenceNumberToPass = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumberToPass == null){
            BigInteger newSeqNum = BigInteger.valueOf(new SecureRandom().nextLong());
            sequenceNumbers.put(pubKeyStr, newSeqNum);
            sequenceNumberToPass = newSeqNum;
        }
        System.out.println("ServerFE-getSeqNum: seqNum to send = " + sequenceNumberToPass);
        byte[] sessionKey = Crypto.generateSessionKey();            // FIXME sessionsKey management
        byte[][] args = new byte[][] {sequenceNumberToPass.toByteArray(), null, null, null };
        Message m = Crypto.getSecureMessage(args, null, sessionKey, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);
        return m;
    }
}

