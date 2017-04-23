package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidDomainException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidPasswordException;
import pt.ulisboa.tecnico.meic.sec.client.exceptions.InvalidUsernameException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.*;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public interface ClientAPI {

    public void init(KeyStore ks, String keystoreName, String keystorePassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException;

    public void register_user() throws RemoteException, InvalidArgumentsException;

    public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidDomainException, InvalidUsernameException, InvalidPasswordException;

    public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, InvalidDomainException, InvalidUsernameException;

    public void close();
}
