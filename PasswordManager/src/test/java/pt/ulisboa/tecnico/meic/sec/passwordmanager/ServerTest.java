package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

public class ServerTest {
	public static byte[] VALID_DOMAIN = "a.b".getBytes(StandardCharsets.UTF_8);
	public static byte[] VALID_USERNAME = "name".getBytes(StandardCharsets.UTF_8);
	public static byte[] INEXISTENT_DOMAIN = "d.e".getBytes(StandardCharsets.UTF_8);
	public static byte[] INEXISTENT_USERNAME = "eman".getBytes(StandardCharsets.UTF_8);
	public static byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);
	
	public Server server = null;
	public Key key = null;
	
	public ServerTest() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(random);
		key = keygen.generateKey();
	}
	
	@Before
	public void setup() throws RemoteException {
		server = new Server();
		server.register(key);
		server.put(key, VALID_DOMAIN, VALID_USERNAME, PASSWORD);
	}
	
	@Test
	public void GetCorrectExecution() {
		byte[] pass;
		try {
			pass = server.get(key, VALID_DOMAIN, VALID_USERNAME);
			assertTrue(new String(pass, StandardCharsets.UTF_8).equals(new String(PASSWORD, StandardCharsets.UTF_8)));
		} catch (Exception e) {
			fail();
			e.printStackTrace();
		}
	}
	
	@Test(expected = InvalidPublicKeyException.class)
	public void GetInvalidPublicKey() throws RemoteException {
		server.get(null, VALID_DOMAIN, VALID_USERNAME);
	}
	
	@Test(expected = InvalidDomainException.class)
	public void GetInvalidDomain() throws RemoteException {
		server.get(key, null, VALID_USERNAME);
	}

	@Test(expected = InvalidDomainException.class)
	public void GetInexistentDomain() throws RemoteException {
		server.get(key, INEXISTENT_DOMAIN, VALID_USERNAME);
	}

	@Test(expected = InvalidUsernameException.class)
	public void GetInvalidUsername() throws RemoteException {
		server.get(key, VALID_DOMAIN, null);
	}

	@Test(expected = InvalidUsernameException.class)
	public void GetInexistentUsername() throws RemoteException {
		server.get(key, VALID_DOMAIN, INEXISTENT_USERNAME);
	}


	@Test
	public void RegisterCorrectExecution() {
		try {
			server = new Server();
			server.register(key);
		} catch (Exception e) {
			fail();
			e.printStackTrace();
		}
	}
	
	@Test(expected = InvalidPublicKeyException.class)
	public void RegisterInvalidKey() throws RemoteException {
		server.register(null);
	}
	
	@Test(expected = DuplicatePublicKeyException.class)
	public void RegisterDuplicateKey() throws RemoteException {
		server.register(key);
	}
}