package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class ServerFrontEnd extends UnicastRemoteObject implements CommunicationAPI{

    public ServerCrypto server;

    protected ServerFrontEnd() throws RemoteException {
        server = new ServerCrypto();
    }

    public void register(Message message) throws RemoteException {

        //TODO: cenas

        //server.register(publicKey);
    }

    public void put(Message message) throws RemoteException {
        //TODO: cenas

        //server.put(publicKey, domain, username, password);
    }

    public byte[] get(Message message) throws RemoteException {
        //TODO: cenas


        //byte[] password = server.get(publicKey, domain, username);

        //TODO: mais cenas e retorna isso
        return new byte[0];    }
}
