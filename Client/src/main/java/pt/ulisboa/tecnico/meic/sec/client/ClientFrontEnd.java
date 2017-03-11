package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;

public class ClientFrontEnd implements CommunicationAPI {

    CommunicationAPI server;

    public ClientFrontEnd(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        server = (CommunicationAPI) Naming.lookup(remoteServerName);
    }

    public void register(Message message) throws RemoteException, DuplicatePublicKeyException, InvalidPublicKeyException {
        //TODO: cenas

        server.register(new Message());
    }

    public void put(Message message) throws RemoteException {
        //TODO: cenas

        server.put(new Message());
    }

    public byte[] get(Message message) throws RemoteException, InvalidPublicKeyException, InvalidDomainException, InvalidUsernameException {
        //TODO: cenas

        server.get(new Message());

        //TODO: mais cenas

        return new byte[0];
    }
}
