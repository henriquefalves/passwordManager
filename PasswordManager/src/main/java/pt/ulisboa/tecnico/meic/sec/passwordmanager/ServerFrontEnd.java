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
    private Map<String, String> sessionKeys;

    protected ServerFrontEnd() throws RemoteException {
        server = new ServerCrypto();
        sequenceNumbers = new HashMap<>();
        sessionKeys = new HashMap<>();
    }

    public void register(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return;
        }

        System.out.println("REGISTER-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        Message result = Crypto.checkMessage(message, sequenceNumber, existingSessionKey, server.server.myPrivateKey, server.server.myPublicKey);
        server.register(message.publicKey);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
        }
    }

    public void put(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return;
        }

        System.out.println("PUT-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        Message result = Crypto.checkMessage(message, sequenceNumber, existingSessionKey, server.server.myPrivateKey, server.server.myPublicKey);

        // TODO Henrique result.passwordIv is received passwordIv

        server.put(message.publicKey, result.domain, result.username, result.password);

        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // !!
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
        }
    }

    public Message get(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        BigInteger sequenceNumber = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumber == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return null;
        }

        System.out.println("GET-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        Message result = Crypto.checkMessage(message, sequenceNumber, existingSessionKey, server.server.myPrivateKey, server.server.myPublicKey);
        byte[] password = server.get(message.publicKey, result.domain, result.username);

        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // save in map
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
        sequenceNumbers.put(pubKeyStr, sequenceNumber);           // save in map

        Message insecureMessage = new Message(sequenceNumber, null, null, password);
        // TODO pass passwordIv and check in ClientCrypto
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, existingSessionKey, false, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);
        return secureMessage;
    }

    public Message getSequenceNumber(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKey.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }

        Message result = Crypto.checkMessage(message, null, existingSessionKey, server.server.myPrivateKey, server.server.myPublicKey);
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        BigInteger sequenceNumberToPass = sequenceNumbers.get(pubKeyStr);
        if(sequenceNumberToPass == null){
            BigInteger newSeqNum = BigInteger.valueOf(new SecureRandom().nextLong());
            sequenceNumbers.put(pubKeyStr, newSeqNum);
            sequenceNumberToPass = newSeqNum;
        }
        System.out.println("ServerFE-getSeqNum: seqNum to send = " + sequenceNumberToPass);
        Message insecureMessage = new Message(sequenceNumberToPass, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, existingSessionKey, false, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);
        return secureMessage;
    }
}

