package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.InexistentTupleException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidUsernameException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ClientAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Client extends UnicastRemoteObject implements ClientAPI {
	private static final String KEYPAIRPASSWORD = "123456";
	private static final String USERALIAS = "henrique";
	private Key myPrivateKey;
	private Key myPublicKey;
	private Key serverPublicKey;
	private ServerAPI passwordManager;

	//CREATED BY: MATEUS -> COMPILE IN TEST CLASS.
	public Client(String remoteServerName) throws RemoteException, MalformedURLException, NotBoundException {
		this.passwordManager = new ClientCrypto(remoteServerName);
	}

	private KeyStore loadKeystore(String keyStoreName, char[] passwordKeyStore){
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		FileInputStream fis=null;

		try {
			fis = new FileInputStream(keyStoreName);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			ks.load(fis, passwordKeyStore);
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
		return ks;

	}

	public void init(KeyStore keystore, String keystoreName, String keystorePassword) {
		
		keystore = loadKeystore(keystoreName, keystorePassword.toCharArray());
		//Get the key with the given alias.
		String serverAlias = "server";


		Key key = null;
		try {
			key = keystore.getKey(USERALIAS, KEYPAIRPASSWORD.toCharArray());
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
				cert = keystore.getCertificate(USERALIAS);
			} catch (KeyStoreException e) {
				System.out.println("Unable to load public and private key");
				e.printStackTrace();
			}

			// Get public key
			PublicKey publicKey = cert.getPublicKey();

			// Return a key pair
			KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
			myPrivateKey = keyPair.getPrivate();
			myPublicKey = keyPair.getPublic();
		}
		try {
			serverPublicKey= keystore.getCertificate(serverAlias).getPublicKey();
		} catch (KeyStoreException e) {
			System.out.println("Unable to load Public Key From Server");
			e.printStackTrace();
		}

		((ClientCrypto)passwordManager).init(myPrivateKey, myPublicKey, serverPublicKey);
	}

	public void register_user() {
			
			try {
			passwordManager.register(myPublicKey);
		} catch (RemoteException e) {
			System.out.println("Client.register_user Unable to register on server");
			e.printStackTrace();
		}

	}

	public void save_password(byte[] domain, byte[] username, byte[] password) {
		if(domain==null) throw new InvalidDomainException();
		if(username==null) throw new InvalidUsernameException();
		if(password==null) throw new InvalidPasswordException();
		try {
			passwordManager.put(myPublicKey, domain, username, password);
		} catch (RemoteException e) {
			System.out.println("Client.save_password Unable to put on server");
			e.printStackTrace();
		}
	}

	public byte[] retrieve_password(byte[] domain, byte[] username) {
		if(domain==null) throw new InvalidDomainException();
		if(username==null) throw new InvalidUsernameException();
		try {
			return passwordManager.get(myPublicKey, domain, username);
		} catch (RemoteException e) {
			System.out.println("Client.save_password Unable to put on server");
			e.printStackTrace();
		}
		catch (InexistentTupleException e) {
			
			//TODO rever como tratar caso o servidor não encontra password paras os dois args
			System.out.println("YOU DO NOT HAVE PASSWORD WITH GIVEN ARGUMENTS");
		}
		return null;
	}

	public void close() {
		myPrivateKey =null;
		myPublicKey= null;
		serverPublicKey=null;
	}
}
