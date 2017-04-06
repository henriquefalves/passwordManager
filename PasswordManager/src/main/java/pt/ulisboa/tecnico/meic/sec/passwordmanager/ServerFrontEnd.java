package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.MissingChallengeException;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Key;
import java.util.*;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    private PrivateKey myPrivateKey;
    private PublicKey myPublicKey;

    private Map<String, ArrayList<byte[]>> challengesMap;
    private Map<String, String> sessionKeys;
    public Server server;

    SecureRandom randomGenerator;

    protected ServerFrontEnd(PrivateKey privateKey, PublicKey publicKey) throws RemoteException {
        this.myPrivateKey = privateKey;
        this.myPublicKey = publicKey;
        server = new Server();

        challengesMap = new HashMap<>();
        sessionKeys = new HashMap<>();
        randomGenerator = new SecureRandom();
    }

    public void register(Message message) throws RemoteException {
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }
        Message result = Crypto.checkMessage(message, existingSessionKey, myPrivateKey, myPublicKey);
        checkChallenge(result.publicKeySender, result.challenge);
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

        Message result = Crypto.checkMessage(message, existingSessionKey, myPrivateKey, myPublicKey);
        checkChallenge(result.publicKeySender, result.challenge);
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

        Message result = Crypto.checkMessage(message, existingSessionKey, myPrivateKey, myPublicKey);
        byte[] challenge = checkChallenge(result.publicKeySender, result.challenge);
        byte[] password = server.get(message.publicKeySender, result.domain, result.username);

        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        Message insecureMessage = new Message(challenge, null, null, password);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, existingSessionKey, false, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }

    public Message getChallenge(Message message) throws RemoteException {

        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());
        String existingSKstring =sessionKeys.get(pubKeyStr);
        byte[] existingSessionKey = null;
        if(existingSKstring != null){
            existingSessionKey = Base64.getDecoder().decode(sessionKeys.get(pubKeyStr));
        }

        Message result = Crypto.checkMessage(message, existingSessionKey, myPrivateKey, myPublicKey);
        if(result.secretKey != null){
            String newSessionKey = Base64.getEncoder().encodeToString(result.secretKey);
            sessionKeys.put(pubKeyStr, newSessionKey);
            existingSessionKey = result.secretKey;
        }

        byte[] challenge = new byte[128];
        randomGenerator.nextBytes(challenge);

        ArrayList<byte[]> challenges = challengesMap.get(pubKeyStr);
        if(challenges == null){
            ArrayList<byte[]> challengesOfClient = new ArrayList<>();
            challengesOfClient.add(challenge);
            challengesMap.put(pubKeyStr, challengesOfClient);
        }
        else{
            challenges.add(challenge);
            challengesMap.put(pubKeyStr, challenges);
        }

        System.out.println("ServerFE-getChallenge: challenge to send = " + new String(challenge, StandardCharsets.UTF_8));
        Message insecureMessage = new Message(challenge, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, existingSessionKey, false, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }


    private byte[] checkChallenge(Key publicKey, byte[] receivedChallenge){
            if(receivedChallenge == null){
                throw new MissingChallengeException();
            }
            String pubKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            ArrayList<byte[]> challenges = challengesMap.get(pubKeyStr);
            if(challenges == null){
                throw new InvalidChallengeException();
            }else{
                for (int i = 0; i < challenges.size(); i++) {
                    if(Arrays.equals(challenges.get(i), receivedChallenge)){
                        byte[] challenge = challenges.get(i);
                        challenges.remove(i);
                        challengesMap.put(pubKeyStr, challenges);
                        System.out.println("Server-FE-checkChallenge: VALID challenge");
                        return challenge;
                    }
                }
                System.out.println("Server-FE-checkChallenge: Invalid challenge");
                throw new InvalidChallengeException();
            }
    }

}

