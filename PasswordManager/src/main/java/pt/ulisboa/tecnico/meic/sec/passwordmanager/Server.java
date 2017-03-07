package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.rmi.RemoteException;
import java.security.Key;

public class Server implements ServerAPI {

	@Override
	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub

	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

	public static void main(String[] args) {

		System.out.println("SUCCESS SERVER");
	}

}
