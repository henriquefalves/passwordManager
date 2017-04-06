package pt.ulisboa.tecnico.meic.sec.client;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;

public interface ClientAPI {

    public void init(KeyStore ks, String keystoreName, String keystorePassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException;

    public void register_user() throws RemoteException, InvalidArgumentsException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, NoSuchPaddingException, InvalidKeyException;

    public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, InvalidDomainException, InvalidUsernameException, InvalidPasswordException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException;

    public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, InvalidDomainException, InvalidUsernameException, InexistentTupleException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException;

    public void close();
}
