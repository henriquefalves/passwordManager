package pt.ulisboa.tecnico.meic.sec.commoninterface;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.*;

import java.rmi.RemoteException;
import java.security.KeyStore;

public interface ClientAPI {

    public void init(KeyStore ks, String keystoreName, String keystorePassword);

    public void register_user() throws RemoteException, InvalidArgumentsException;

    public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidDomainException, InvalidUsernameException, InvalidPasswordException;

    public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, InvalidDomainException, InvalidUsernameException, InexistentTupleException;

    public void close();
}
