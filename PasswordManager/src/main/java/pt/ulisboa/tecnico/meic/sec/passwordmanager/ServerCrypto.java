package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.rmi.RemoteException;
import java.security.Key;

public class ServerCrypto implements ServerAPI {

    public Server server;

    public ServerCrypto() throws RemoteException {
        server = new Server();
    }

    public void register(Key publicKey, int sequenceNumber) throws RemoteException {

        //TODO: cenas

        server.register(publicKey, sequenceNumber);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, int sequenceNumber) throws RemoteException {

        //TODO: cenas

        server.put(publicKey, domain, username, password, sequenceNumber);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username, int sequenceNumber) throws RemoteException {
        //TODO: cenas


        byte[] password = server.get(publicKey, domain, username, sequenceNumber);

        //TODO: mais cenas e retorna isso
        return new byte[0];    }

    @Override
    public int getSequenceNumber(Key publicKey) throws RemoteException, InvalidArgumentsException {
        return 0;
    }
}
