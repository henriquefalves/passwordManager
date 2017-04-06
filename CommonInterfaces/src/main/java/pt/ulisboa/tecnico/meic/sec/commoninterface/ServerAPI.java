package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface ServerAPI extends Remote{

	//Specification: registers the user in the server. Anomalous or unauthorized
	//requests should return an appropriate exception or error code
	public void register(Key publicKey) throws RemoteException, DuplicatePublicKeyException, InvalidArgumentsException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException;
	
	//Specification: stores the triple (domain, username, password) on the server.
	//This corresponds to an insertion if the (domain, username) pair is not already
	//	known by the server, or to an update otherwise. Anomalous or unauthorized
	//requests should return an appropriate exception or error code
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidArgumentsException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException;
	
	//Specification: retrieves the password associated with the given (domain,
	//username) pair. Anomalous or unauthorized requests should return an
	//appropriate exception or error code.
	public byte[] get(Key publicKey, byte[] domain, byte[] username)
			throws RemoteException, InvalidArgumentsException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException;

}
