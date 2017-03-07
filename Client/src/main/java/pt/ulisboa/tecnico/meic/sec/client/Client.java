package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ClientAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class Client extends UnicastRemoteObject implements ClientAPI {
	private ServerAPI passwordManager;

	public Client(ServerAPI passwordManager) throws RemoteException {
		this.passwordManager = passwordManager;
	}
}
