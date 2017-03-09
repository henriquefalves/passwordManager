package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.util.Vector;

public class Server extends UnicastRemoteObject implements ServerAPI {
	private Vector<User> users;

	public Server() throws RemoteException {
		super();
		users = new Vector<User>();
	}

	@Override
	public void register(Key publicKey) throws RemoteException {
		if (publicKey == null) {
			throw new InvalidPublicKeyException();
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				throw new DuplicatePublicKeyException();
			}
		}
		User newUser = new User(publicKey);
		users.addElement(newUser);
		System.out.println("register: Success");
	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		for (User u : users){
			if (u.isUserKey(publicKey)){
				u.updateInfo(domain, username, password);
				System.out.println("put: Success");
				return;
			}
		}
		System.out.println("put: Unknown user");
		// TODO exception - unknown user
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		if (publicKey == null){ throw new InvalidPublicKeyException(); }
		if (domain == null) {throw new InvalidDomainException(); }
		if (username == null) {throw new InvalidUsernameException(); }
		for (User u : users){
			if (u.isUserKey(publicKey)){
				System.out.println("get: Success");
				return u.getPassword(domain, username);
			}
		}
		// TODO exception - unknown user
		System.out.println("get: Unknown user");
		throw new InvalidDomainException();
	}

}
