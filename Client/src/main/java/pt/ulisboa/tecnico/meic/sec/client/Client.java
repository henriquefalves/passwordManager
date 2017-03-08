package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ClientAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStore;

public class Client extends UnicastRemoteObject implements ClientAPI {
	private ServerAPI passwordManager;

	public Client(ServerAPI passwordManager) throws RemoteException {
		this.passwordManager = passwordManager;
	}

	//CREATED BY: MATEUS -> COMPILE IN TEST CLASS.
	public Client() throws RemoteException {

    }

    public void init(KeyStore ks) {

    }

    public void register_user() {

    }

    public void save_password(byte[] domain, byte[] username, byte[] password) {

    }

    public byte[] retrieve_password(byte[] domain, byte[] username) {
        return new byte[0];
    }

    public void close() {

    }
}
