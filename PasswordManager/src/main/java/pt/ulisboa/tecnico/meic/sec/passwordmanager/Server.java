package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Vector;

public class Server implements ServerAPI {
	private Vector<User> users;


	public Server() throws RemoteException {
		users = new Vector<User>();
	}

	public void register(Key publicKey) throws RemoteException {
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
		System.out.println("register: Success");
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		if (publicKey == null || domain == null || username == null){
			throw new InvalidArgumentsException();
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				u.updateInfo(domain, username, password);
				System.out.println("put: Success");
				return;
			}
		}
		System.out.println("put: Unknown user");
		throw new InvalidArgumentsException();	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		if (publicKey == null || domain == null || username == null){
			{throw new InvalidArgumentsException(); }
		}
		for (User u : users){
			if (u.isUserKey(publicKey)){
				System.out.println("get: Success");
				return u.getPassword(domain, username);
			}
		}
		System.out.println("get: Unknown user");
		throw new InvalidArgumentsException();
	}

	public void put(Key publicKeySender, byte[] domain, byte[] username, byte[] password,
			SignatureAutentication signatureAutentication) {
		if (publicKeySender == null || domain == null || username == null){
			throw new InvalidArgumentsException();
		}
		for (User u : users){
			if (u.isUserKey(publicKeySender)){
				u.updateInfo(domain, username, password,signatureAutentication);
				System.out.println("put: Success");
				return;
			}
		}
		System.out.println("put: Unknown user");
		throw new InvalidArgumentsException();

	}


}
