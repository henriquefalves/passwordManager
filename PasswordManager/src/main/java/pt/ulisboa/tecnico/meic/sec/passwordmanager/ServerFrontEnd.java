package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    private PrivateKey myPrivateKey;
    private PublicKey myPublicKey;
    private Map<String, byte[]> challengesMap;
    private Map<String, String> sessionKeys;
    public Server server;

    protected ServerFrontEnd(PrivateKey privateKey, PublicKey publicKey) throws RemoteException {
        this.myPrivateKey = privateKey;
        this.myPublicKey = publicKey;
        server = new Server();

        challengesMap = new HashMap<>();
        sessionKeys = new HashMap<>();
    }

    public void register(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        byte[] challengeToCompare = challengesMap.get(pubKeyStr);
        if(challengeToCompare == null){
            System.out.println("ServerFE-register: Inexistent publicKey");
            return;
        }
        Message result = Crypto.checkMessage(message, challengeToCompare, existingSessionKey, myPrivateKey, myPublicKey);
        server.register(message.publicKeySender);
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
        }
    }

    public void put(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        byte[] challenge = challengesMap.get(pubKeyStr);
        if(challenge == null){
            System.out.println("ServerFE-register: Inexistent publicKey, must generate Challege");
            return;
        }

        System.out.println("PUT-seqNumToCompare = " + new String(challenge, StandardCharsets.UTF_8));
        Message result = Crypto.checkMessage(message, challenge, existingSessionKey, myPrivateKey, myPublicKey);

        SignatureAutentication signatureAutentication = new SignatureAutentication(message.randomIv, message.publicKeySender, myPublicKey, message.challenge, message.domain, message.username,message.password, message.signature);
        server.put(message.publicKeySender, result.domain, result.username, result.password , signatureAutentication);

        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
        }
    }

    public Message get(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        byte[] challenge = challengesMap.get(pubKeyStr);
        if(challenge == null){
            System.out.println("ServerFE-register: Inexistent publicKey, , must generate Challege");
            return null;
        }

        System.out.println("GET-seqNumToCompare = " +  new String(challenge, StandardCharsets.UTF_8));
        Message result = Crypto.checkMessage(message, challenge, existingSessionKey, myPrivateKey, myPublicKey);
        byte[] password = server.get(message.publicKeySender, result.domain, result.username);

        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        Message insecureMessage = new Message(challenge, null, null, password);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, existingSessionKey, false, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }

    public Message getChallenge(Message message) throws RemoteException {

        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }

        Message result = Crypto.checkMessage(message, null, existingSessionKey, myPrivateKey, myPublicKey);
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        SecureRandom random = new SecureRandom();
        byte[] challenge= random.generateSeed(128);

        challengesMap.put(pubKeyStr, challenge);


        System.out.println("ServerFE-getChallenge: challenge to send = " + new String(challenge, StandardCharsets.UTF_8));
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, null, existingSessionKey, false, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }
}

