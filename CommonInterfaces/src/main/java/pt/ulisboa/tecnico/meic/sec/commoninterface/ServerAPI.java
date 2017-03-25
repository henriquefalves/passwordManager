package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;

public interface ServerAPI extends Remote{

	//Specification: registers the user in the server. Anomalous or unauthorized
	//requests should return an appropriate exception or error code
	public void register(Key publicKey) throws RemoteException, DuplicatePublicKeyException, InvalidArgumentsException;
	
	//Specification: stores the triple (domain, username, password) on the server.
	//This corresponds to an insertion if the (domain, username) pair is not already
	//	known by the server, or to an update otherwise. Anomalous or unauthorized
	//requests should return an appropriate exception or error code
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidArgumentsException;
	
	//Specification: retrieves the password associated with the given (domain,
	//username) pair. Anomalous or unauthorized requests should return an
	//appropriate exception or error code.
	public byte[] get(Key publicKey, byte[] domain, byte[] username)
	throws RemoteException, InvalidArgumentsException;

}
