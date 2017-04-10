package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.*;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

public class Server implements ServerAPI,Serializable {

	private ConcurrentHashMap<Key, User> users;


	public Server() throws RemoteException {
		users = new ConcurrentHashMap<Key, User>();
	}

	public void register(Key publicKey) throws RemoteException {
		if (publicKey == null) {
			throw new InvalidArgumentsException();
		}
		if(users.containsKey(publicKey))
			throw new DuplicatePublicKeyException();

		User newUser = new User(publicKey);
		users.put(publicKey,newUser);
	}

	@Deprecated
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {

		if (publicKey == null || domain == null || username == null){
			throw new InvalidArgumentsException();

	}
		if(users.containsKey(publicKey)){
		users.get(publicKey).updateInfo(domain, username, password);
		return;

	}
		throw new InvalidArgumentsException();
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {

		if (publicKey == null || domain == null || username == null){
			{throw new InvalidArgumentsException(); }
		}
		if(users.containsKey(publicKey)) {
			byte[] password = users.get(publicKey).getPassword(domain, username);
			return password;
		}
			throw new InvalidArgumentsException();
	}

	public void put(Key publicKeySender, byte[] domain, byte[] username, byte[] password,
		UserData signatureAuthentication) {

		if (publicKeySender == null || domain == null || username == null){
			throw new InvalidArgumentsException();
		}
		if(users.containsKey(publicKeySender)){

			users.get(publicKeySender).updateInfo(domain, username, password, signatureAuthentication);
			return;

		}
		throw new InvalidArgumentsException();
	}


	public void importObjects(){
		String folder = System.getProperty("user.dir");
		FileInputStream fi = null;
		int counter = 0;
		boolean exitsFiles=true;
		while(exitsFiles) {
			try {
				fi = new FileInputStream(new File(folder + File.separator + "DataUser" + counter + ".txt"
				));
				ObjectInputStream oi = new ObjectInputStream(fi);
				UserData data = (UserData) oi.readObject();
				oi.close();
				fi.close();
				if (users.containsKey(data.publicKeySender))
					users.get(data.publicKeySender).updateInfo(data.domain, data.username, data.password, data);
				else {
					users.put(data.publicKeySender, new User(data.publicKeySender));
					users.get(data.publicKeySender).updateInfo(data.domain, data.username, data.password, data);
				}
				counter++;
			} catch (FileNotFoundException e) {
				exitsFiles = false;
			} catch (IOException e) {
				exitsFiles = false;
			} catch (ClassNotFoundException e) {
				exitsFiles = false;

			}
		}
		System.out.println("LOADED "+ counter+" Passwords");

	}


	public void numberOfUsers() {
		int count=0;
		for (User value : users.values()) {
			count++;
		}
		System.out.println("NumberOfUsers="+count);
	}

	public void numberOfPasswords() {
		Iterator it = users.entrySet().iterator();
		int count=0;
		for (User userX : users.values()) {
			count=count+userX.numberOfPasswords();
		}
		System.out.println("NumberOfPasswords="+count);
	}
}
