package pt.ulisboa.tecnico.meic.sec.client;

import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InexistentTupleException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import java.nio.charset.StandardCharsets;

public class ClientTest {
	
	public static byte[] VALID_DOMAIN = "a.b".getBytes(StandardCharsets.UTF_8);
	public static byte[] VALID_USERNAME = "name".getBytes(StandardCharsets.UTF_8);
	public static byte[] PASSWORD1 = "password1".getBytes(StandardCharsets.UTF_8);
	public static byte[] PASSWORD2 = "password2".getBytes(StandardCharsets.UTF_8);
	
	public Client client = null;
	
	//TODO: TEST WITH MINIMUM CHARACTERS FOR CIPHER AFTER DECIDING HOW WE WILL CIPHER
	
    @Before
    public void setUp() throws Exception {
		client = new Client();
		//TODO: initialize client with valid KeyStore. Will do after implementing init method.
		//client.init();
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
	public void SavePasswordInvalidDomain() {
		client.save_password(null, VALID_USERNAME, PASSWORD1);
	}
	
	@Test(expected = InvalidUsernameException.class)
	public void SavePasswordInvalidUsername() {
		client.save_password(VALID_DOMAIN, null, PASSWORD1);
	}
	
	@Test(expected = InvalidPasswordException.class)
	public void SavePasswordInvalidPassword() {
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
	public void RetrievePasswordInvalidDomain() {
		client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
		client.retrieve_password(null, VALID_USERNAME);
	}
	
	@Test(expected = InvalidUsernameException.class)
	public void RetrievePasswordInvalidUsername()	{
		client.save_password(VALID_DOMAIN, VALID_USERNAME, PASSWORD1);
		client.retrieve_password(VALID_DOMAIN, null);
	}
	
	@Test(expected = InexistentTupleException.class)
	public void RetrievePasswordInvalidTuple() {
		client.retrieve_password(VALID_DOMAIN, VALID_USERNAME);
	}
}