package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.rmi.Remote;
import java.rmi.RemoteException;


public interface CommunicationAPI extends Remote{

    public void register(Message message) throws RemoteException, DuplicatePublicKeyException, InvalidArgumentsException;

    public void put(Message message) throws RemoteException;

    public Message get(Message message) throws RemoteException, InvalidArgumentsException;

    public Message getSequenceNumber(Message message) throws RemoteException;
}
