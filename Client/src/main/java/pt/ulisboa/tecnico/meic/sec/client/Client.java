package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InexistentTupleException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

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
	private static final String SERVER_ALIAS = "server";
	private static final String USERALIAS = "user";
	private Key myPublicKey;
	private Key myPrivateKey;

	private ServerAPI passwordManager;

	public Client(String remoteServerName) throws RemoteException, MalformedURLException, NotBoundException {
		this.passwordManager = new ClientFrontEnd(remoteServerName);
	}

	private KeyStore loadKeystore(KeyStore keystore, String keyStoreName, char[] passwordKeyStore) throws NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = keystore;

		FileInputStream fis=null;
        fis = new FileInputStream(keyStoreName);
        ks.load(fis, passwordKeyStore);
        if(fis != null )
            fis.close();
		return ks;
	}

	public void init(KeyStore keystore, String keystoreName, String keystorePassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {

		//Get the key with the given alias.
		keystore = loadKeystore( keystore , keystoreName, keystorePassword.toCharArray());

		Key key = keystore.getKey(USERALIAS,  "".toCharArray());

		if (key instanceof PrivateKey) {

			// Get certificate of public key
			java.security.cert.Certificate cert = null;
			cert = keystore.getCertificate(USERALIAS);

			// Get public key
			PublicKey publicKey = cert.getPublicKey();

			// Return a key pair
			KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
			myPrivateKey = keyPair.getPrivate();
			myPublicKey = keyPair.getPublic();
			System.out.println(myPublicKey);
		}

		PublicKey serverPublicKey = null;
		serverPublicKey= keystore.getCertificate(SERVER_ALIAS).getPublicKey();

		((ClientFrontEnd)passwordManager).init(myPrivateKey, myPublicKey, serverPublicKey);

	}

	public void register_user() throws RemoteException, InvalidArgumentsException {
		passwordManager.register(myPublicKey);
	}

	/* 
	 * Before storing the password is encrypted with publicKey of client
	 */
	public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidDomainException, InvalidUsernameException,  InvalidPasswordException {
		if(domain==null) throw new InvalidDomainException();
		if(username==null) throw new InvalidUsernameException();
		if(password==null) throw new InvalidPasswordException();

		byte[] hashDomain = Crypto.hashData(domain);
		byte[] hashUsername = Crypto.hashData(domain);
		byte[] encryptedPassword = Crypto.encryptAsymmetric(password, myPublicKey, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);
		
		passwordManager.put(myPublicKey, hashDomain, hashUsername, encryptedPassword);
	}

	/* 
	 * Before retrived the password is decrypted with privateKey
	 */
	public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, InvalidDomainException, InvalidUsernameException, InexistentTupleException {
		if(domain==null) throw new InvalidDomainException();
		if(username==null) throw new InvalidUsernameException();
		
		byte[] hashDomain = Crypto.hashData(domain);
		byte[] hashUsername = Crypto.hashData(domain);
		byte[] encryptedPassword = passwordManager.get(myPublicKey, hashDomain, hashUsername);
		byte[] decryptedPassword = Crypto.decryptAsymmetric(encryptedPassword, myPrivateKey, Crypto.ASYMETRIC_CIPHER_ALGORITHM1);

		return decryptedPassword;
	}

	public void close() {
		myPublicKey= null;
	}
}
