package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import javafx.util.Pair;
import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.CorruptedMessageException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidChallengeException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.MissingChallengeException;

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

    // contains the list of valid challenges for each PubKey
    private Map<String, ArrayList<byte[]>> challengesMap;
    public Server server;

    SecureRandom randomGenerator;

    protected ServerFrontEnd(PrivateKey privateKey, PublicKey publicKey) throws RemoteException {
        this.myPrivateKey = privateKey;
        this.myPublicKey = publicKey;
        server = new Server();

        challengesMap = new HashMap<>();
        randomGenerator = new SecureRandom();
    }

    public void register(Message message) throws RemoteException {
        if(message.publicKeySender == null){
            throw new CorruptedMessageException();
        }
        Message result = Crypto.checkMessage(message, myPrivateKey, myPublicKey);
        checkChallenge(result.publicKeySender, result.challenge);
        server.register(message.publicKeySender);
    }

    public void put(Message message) throws RemoteException {
        if(message.publicKeySender == null){
            throw new CorruptedMessageException();
        }

        Message result = Crypto.checkMessage(message, myPrivateKey, myPublicKey);
        checkChallenge(result.publicKeySender, result.challenge);
        UserData dataTransfer = new UserData(result.randomIv, result.publicKeySender, myPublicKey, result.challenge, result.domain, result.username,result.password, result.signature,result.wts);
        server.put(message.publicKeySender, result.domain, result.username, result.password , dataTransfer);
    }

    public Message get(Message message) throws RemoteException {
        if(message.publicKeySender == null){
            throw new CorruptedMessageException();
        }

        Message decipheredMessage = Crypto.checkMessage(message, myPrivateKey, myPublicKey);
        byte[] challenge = checkChallenge(decipheredMessage.publicKeySender, decipheredMessage.challenge);
        Pair<byte[], byte[]> pair = server.newGet(message.publicKeySender, decipheredMessage.domain, decipheredMessage.username);
        byte[] password = pair.getKey();
        byte[] ts = pair.getValue();
        //TODO BY MATEUS: NAO ME LEMBRO PARA QUE NECESSITAMOS DO TIMESTAMP
        //TODO BY MATEUS: POR ISSO NAO ESTOU A FAZER NADA COM ELE. ELUCIDEM-ME PLS
        //Comment because of tests
        // System.out.println(Crypto.byteArrayToLeInt(decipheredMessage.rid));
        Message insecureMessage = new Message(challenge, null, null, password, null, decipheredMessage.rid, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, decipheredMessage.secretKey, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }

    public Message getChallenge(Message message) throws RemoteException {
        if(message.publicKeySender == null){
            throw new CorruptedMessageException();
        }
        String pubKeyStr = Base64.getEncoder().encodeToString(message.publicKeySender.getEncoded());

        Message result = Crypto.checkMessage(message, myPrivateKey, myPublicKey);

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

        Message insecureMessage = new Message(challenge, null, null, null, null, null, null);
        Message secureMessage = Crypto.getSecureMessage(insecureMessage, result.secretKey, myPrivateKey, myPublicKey, message.publicKeySender);
        return secureMessage;
    }

    private byte[] checkChallenge(Key publicKey, byte[] receivedChallenge) {
        if(receivedChallenge == null) {
            throw new MissingChallengeException();
        }
        String pubKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        ArrayList<byte[]> challenges = challengesMap.get(pubKeyStr);
        if(challenges == null) {
            throw new InvalidChallengeException();
        } else {
            for (int i = 0; i < challenges.size(); i++) {
                if(Arrays.equals(challenges.get(i), receivedChallenge)){
                    byte[] challenge = challenges.get(i);
                    challenges.remove(i);
                    challengesMap.put(pubKeyStr, challenges);
                    return challenge;
                }
            }
            throw new InvalidChallengeException();
        }
    }
}

