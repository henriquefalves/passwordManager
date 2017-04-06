package pt.ulisboa.tecnico.meic.sec.client;


import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assert;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.*;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ClientTest {


	public static byte[] VALID_DOMAIN = "a.b".getBytes(StandardCharsets.UTF_8);
	public static byte[] VALID_USERNAME = "name".getBytes(StandardCharsets.UTF_8);
	public static byte[] PASSWORD1 = "password1".getBytes(StandardCharsets.UTF_8);
	public static byte[] PASSWORD2 = "password2".getBytes(StandardCharsets.UTF_8);

	public static Client client = null;

    @BeforeClass
    public static void setUp() throws Exception {
		client = new Client("rmi://localhost:8006/password-manager");

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JCEKS");
        } catch (KeyStoreException e) {
            System.out.println("Unable to create Keystore");
        }

        String keystoreName = "henriqueKeyStore.jks";
        String keystorePassword = "henrique123";
        client.init(ks, keystoreName, keystorePassword);
		client.register_user();
    }

    @Test
    public void SavePasswordSuccess() {
        try {
			client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
		} catch (Exception e) {
			fail();
			e.printStackTrace();
		}
    }

	@Test
	public void SavePasswordTwiceSucess() {
		try {
			client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
			client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD2);
		} catch (Exception e) {
			fail();
			e.printStackTrace();
		}
	}

	@Test(expected = InvalidDomainException.class)
	public void SavePasswordInvalidDomain() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.save_password(null, VALID_USERNAME, PASSWORD1);
	}

	@Test(expected = InvalidUsernameException.class)
	public void SavePasswordInvalidUsername() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.save_password(VALID_DOMAIN, null, PASSWORD1);
	}

	@Test(expected = InvalidPasswordException.class)
	public void SavePasswordInvalidPassword() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.save_password(VALID_DOMAIN, VALID_USERNAME, null);
	}

	@Test
	public void RetrievePasswordSuccess() {
		try {
			client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
			byte[] pass = client.retrieve_password(VALID_DOMAIN, VALID_USERNAME);
			assertTrue(new String(pass, StandardCharsets.UTF_8).equals(new String(PASSWORD1, StandardCharsets.UTF_8)));
		} catch (Exception e) {
			fail();
			e.printStackTrace();
		}
	}

	@Test(expected = InvalidDomainException.class)
	public void RetrievePasswordInvalidDomain() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
		client.retrieve_password(null, VALID_USERNAME);
	}

	@Test(expected = InvalidUsernameException.class)
	public void RetrievePasswordInvalidUsername() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
		client.retrieve_password(VALID_DOMAIN, null);
	}

	@Test(expected = InvalidArgumentsException.class)
	public void RetrievePasswordInvalidTuple() throws RemoteException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException {
		client.retrieve_password(VALID_DOMAIN, VALID_USERNAME);
	}
}
