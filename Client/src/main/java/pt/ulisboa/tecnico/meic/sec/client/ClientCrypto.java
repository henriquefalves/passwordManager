package pt.ulisboa.tecnico.meic.sec.client;

import com.sun.corba.se.spi.activation.Server;
import pt.ulisboa.tecnico.meic.sec.commoninterface.CommunicationAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Message;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.Key;

public class ClientCrypto implements ServerAPI {

    CommunicationAPI passwordmanager;

    public ClientCrypto(String remoteServerName) throws RemoteException, NotBoundException, MalformedURLException {
        passwordmanager = new ClientFrontEnd(remoteServerName);
    }

    public void register(Key publicKey) throws RemoteException, DuplicatePublicKeyException, InvalidPublicKeyException {
        //TODO: cenas

        passwordmanager.register(new Message());
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
        //TODO: cenas

        passwordmanager.put(new Message());

    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException, InvalidPublicKeyException, InvalidDomainException, InvalidUsernameException {
        //TODO: cenas

        passwordmanager.get(new Message());

        //TODO: mais cenas

        return new byte[0];
    }
}
