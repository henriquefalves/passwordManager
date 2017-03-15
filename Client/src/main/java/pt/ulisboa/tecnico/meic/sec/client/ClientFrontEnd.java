package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

public class ClientFrontEnd implements CommunicationAPI {

    CommunicationAPI server;

    public ClientFrontEnd(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        server = (CommunicationAPI) Naming.lookup(remoteServerName);
    }

    public void register(Message message) throws RemoteException {
        //TODO: cenas

        server.register(message);
    }

    public void put(Message message) throws RemoteException {
        //TODO: cenas

        server.put(new Message());
    }

    public byte[] get(Message message) throws RemoteException {
        //TODO: cenas

        byte[] result = server.get(new Message());

        //TODO: mais cenas

        return result;
    }

    public int getSequenceNumber(Message message) throws RemoteException {
        server.getSequenceNumber(new Message());

        return 0;
    }
}
