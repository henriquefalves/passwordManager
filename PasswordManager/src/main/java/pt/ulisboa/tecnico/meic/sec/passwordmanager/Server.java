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
	private PrivateKey myPrivateKey;
	private PublicKey myPublicKey;
	private static final String KEYSTORENAME= "server.jks";
	private static final String KEYSTOREPASS= "server123";

	public Server() throws RemoteException {
		users = new Vector<User>();
		loadKeys();
	}

	public void register(Key publicKey, int sequenceNumber) throws RemoteException {
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

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password, int sequenceNumber) throws RemoteException {
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

	public byte[] get(Key publicKey, byte[] domain, byte[] username, int sequenceNumber) throws RemoteException {
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

	@Override
	public int getSequenceNumber(Key publicKey) throws RemoteException, InvalidArgumentsException {
		//TODO: retrieve sequence number from client
		return 0;
	}

	private void loadKeys(){

		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		FileInputStream fis=null;

		try {
			fis = new FileInputStream(KEYSTORENAME);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			ks.load(fis, KEYSTOREPASS.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally{
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}


		Key key = null;
		try {
			key = ks.getKey("server", "123456".toCharArray());
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			java.security.cert.Certificate cert = null;
			try {
				cert = ks.getCertificate("server");
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// Get public key
			PublicKey publicKey = cert.getPublicKey();

			// Return a key pair
			KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
			myPrivateKey = keyPair.getPrivate();
			myPublicKey = keyPair.getPublic();

		}
	}
}
