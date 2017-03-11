package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidUsernameException;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;


public interface CommunicationAPI extends Remote{

    public void register(Message message) throws RemoteException, DuplicatePublicKeyException, InvalidPublicKeyException;

    public void put(Message message) throws RemoteException;

    public byte[] get(Message message) throws RemoteException, InvalidPublicKeyException, InvalidDomainException, InvalidUsernameException;
}
