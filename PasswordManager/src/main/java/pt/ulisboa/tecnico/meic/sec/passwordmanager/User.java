package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.Serializable;
import java.security.Key;
import java.util.Base64;
import java.util.Hashtable;


public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    private Key publicKey;
    private Hashtable<String, UserData> mapPasswords;

    public User(Key publicKey){
        this.publicKey = publicKey;
        mapPasswords = new Hashtable<>();
    }

    public boolean isUserKey(Key key){
        return key.equals(this.publicKey);
    }


    /**
     * This method should be eliminated since the signature is stored
     */
    @Deprecated
    public void updateInfo(byte[] domain, byte[] username, byte[] password){

        byte[] concatenateData = Crypto.concatenateData(new byte[][]{domain, username});
        byte[] preKey = Crypto.hashData(concatenateData);
        String key = Base64.getEncoder().encodeToString(preKey);

        if (mapPasswords.containsKey(key)) {                    // unknown domain

            mapPasswords.replace(key, new UserData(null,null, null,null,null,null,password,null));

        } else {
            mapPasswords.put(key, new UserData(null,null, null,null,null,null,password,null));

        }

    }

    public byte[] getPassword(byte[] domain, byte[] username) {
        byte[] concatenateData = Crypto.concatenateData(new byte[][]{domain, username});
        byte[] preKey = Crypto.hashData(concatenateData);
        String key = Base64.getEncoder().encodeToString(preKey);

        UserData signatureAuthentication = mapPasswords.get(key);
        if(signatureAuthentication == null) {
            throw new InvalidArgumentsException();
        }
        return signatureAuthentication.password;
    }

	public void updateInfo(byte[] domain, byte[] username, byte[] password, UserData signatureAuthentication) {
        byte[] concatenateData = Crypto.concatenateData(new byte[][]{signatureAuthentication.domain, signatureAuthentication.username});
        byte[] preKey = Crypto.hashData(concatenateData);
        String key = Base64.getEncoder().encodeToString(preKey);

        if (mapPasswords.containsKey(key)) {                    // unknown domain

            mapPasswords.replace(key, signatureAuthentication);

        } else {
            mapPasswords.put(key, signatureAuthentication);

        }

    }
}
