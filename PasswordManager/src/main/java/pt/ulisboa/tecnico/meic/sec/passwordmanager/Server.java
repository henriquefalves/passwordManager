package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.*;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.Vector;

public class Server implements ServerAPI,Serializable {

	private static final long serialVersionUID = 1L;

	private Vector<User> users;
	private int clock=0;


	public Server() throws RemoteException {
		users = new Vector<User>();
	}

	public void register(Key publicKey) throws RemoteException {
		clock++;
		if (publicKey == null) {
			throw new InvalidArgumentsException();
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				throw new DuplicatePublicKeyException();
			}
		}
		User newUser = new User(publicKey);
		users.addElement(newUser);

	}
	@Deprecated
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		clock++;

		if (publicKey == null || domain == null || username == null){
			throw new InvalidArgumentsException();
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				u.updateInfo(domain, username, password);
				return;
			}
		}
		throw new InvalidArgumentsException();	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		clock++;

		if (publicKey == null || domain == null || username == null){
			{throw new InvalidArgumentsException(); }
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				return u.getPassword(domain, username);
			}
		}
		throw new InvalidArgumentsException();
	}

	public void put(Key publicKeySender, byte[] domain, byte[] username, byte[] password,
			SignatureAuthentication signatureAuthentication) {
		clock++;

		if (publicKeySender == null || domain == null || username == null){
			throw new InvalidArgumentsException();
		}
		for (User u : users){
			if (u.isUserKey(publicKeySender)){
				u.updateInfo(domain, username, password, signatureAuthentication);
				return;
			}
		}
		throw new InvalidArgumentsException();

	}
	public void saveServerState(){
		String folder = System.getProperty("user.dir");

		try {
			FileOutputStream fileOutputStream = new FileOutputStream(folder + File.separator + "stateAt-"+clock+".state" );
			ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
			outputStream.writeObject(this);
			outputStream.close();
		} catch (IOException ioe) {
			System.out.println("Error writing state to file");
		}


	}


}
