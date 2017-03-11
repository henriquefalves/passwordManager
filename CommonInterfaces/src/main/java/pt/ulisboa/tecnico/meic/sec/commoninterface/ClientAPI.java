package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.security.KeyStore;

public interface ClientAPI {

    public void init(KeyStore ks, String keystoreName, String keystorePassword);

    public void register_user();

    public void save_password(byte[] domain, byte[] username, byte[] password);

    public byte[] retrieve_password(byte[] domain, byte[] username);

    public void close();
}
