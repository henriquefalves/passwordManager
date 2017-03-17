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

    public void register(Key publicKey) throws RemoteException {

        server.register(publicKey);
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {

        server.put(publicKey, domain, username, password);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {

        byte[] password = server.get(publicKey, domain, username);

        return password;
    }

}
