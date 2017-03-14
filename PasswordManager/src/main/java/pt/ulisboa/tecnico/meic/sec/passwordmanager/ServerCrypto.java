package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import java.rmi.RemoteException;
import java.security.Key;

/**
 * Created by mateu on 11/03/2017.
 */
public class ServerCrypto implements ServerAPI {

    public Server server;

    public ServerCrypto() throws RemoteException {
        server = new Server();
    }

    public void register(Key publicKey) throws RemoteException {

        //TODO: cenas

        server.register(publicKey);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {

        //TODO: cenas

        server.put(publicKey, domain, username, password);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        //TODO: cenas


        byte[] password = server.get(publicKey, domain, username);

        //TODO: mais cenas e retorna isso
        return new byte[0];    }
}
