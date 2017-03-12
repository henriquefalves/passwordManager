package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;

public class ClientCrypto implements ServerAPI {

    CommunicationAPI passwordmanager;

    public ClientCrypto(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = new ClientFrontEnd(remoteServerName);
    }

    public void register(Key publicKey) throws RemoteException {
        //TODO: cenas

        passwordmanager.register(new Message());
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        //TODO: cenas

        passwordmanager.put(new Message());

    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
        //TODO: cenas

        passwordmanager.get(new Message());

        //TODO: mais cenas

        return new byte[0];
    }
}
