package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    public ServerCrypto server;
    private BigInteger sequenceNumber;

    protected ServerFrontEnd() throws RemoteException {
        server = new ServerCrypto();
        sequenceNumber = BigInteger.valueOf(new SecureRandom().nextLong());
    }

    public void register(Message message) throws RemoteException {

        System.out.println("REGISTER-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {false, false, false, false, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        server.register(message.publicKey);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
    }

    public void put(Message message) throws RemoteException {

        System.out.println("PUT-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {true, true, true, true, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        System.out.println("Server-put: domain = " + new String(result[0], StandardCharsets.UTF_8));
        System.out.println("Server-put: username = " + new String(result[1], StandardCharsets.UTF_8));
        System.out.println("Server-put: password = " + new String(result[2], StandardCharsets.UTF_8));
        System.out.println("Server-put: passwordIV = " + new String(result[3], StandardCharsets.UTF_8));

        // TODO Henrique result[3] is received passwordIv

        server.put(message.publicKey, result[0], result[1], result[2]);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
    }

    public Message get(Message message) throws RemoteException {

        System.out.println("GET-seqNumToCompare = " + sequenceNumber.add(BigInteger.ONE));
        boolean[] argsToGet = new boolean[] {true, true, false, false, false};
        byte[][] result = Crypto.checkMessage(message, sequenceNumber, argsToGet, null, server.server.myPrivateKey, server.server.myPublicKey);
        System.out.println("Server-get: domain = " + new String(result[0], StandardCharsets.UTF_8));
        System.out.println("Server-get: username = " + new String(result[1], StandardCharsets.UTF_8));
        byte[] password = server.get(message.publicKey, result[0], result[1]);
        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++


        sequenceNumber = sequenceNumber.add(BigInteger.ONE);     // seqNum++
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

        // TODO check copy-paste !!!

        BigInteger sequenceNumberToPass = sequenceNumber;      // TODO change to get of seqNum of publicKey
        System.out.println("ServerFE-getSeqNum: seqNum to send = " + sequenceNumberToPass);
        byte[] sessionKey = Crypto.generateSessionKey();            // FIXME sessionsKey management
        byte[][] args = new byte[][] {sequenceNumberToPass.toByteArray(), null, null, null };
        Message m = Crypto.getSecureMessage(args, null, sessionKey, server.server.myPrivateKey, server.server.myPublicKey, message.publicKey);
        return m;
    }
}

