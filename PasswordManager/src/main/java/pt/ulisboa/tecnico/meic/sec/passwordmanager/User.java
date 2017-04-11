package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.*;
import java.security.Key;
import java.util.Base64;
import java.util.Hashtable;


public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    private Key publicKey;
    private Hashtable<String, UserData> mapPasswords;
    private int counter;

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
    public void updateInfo(byte[]  hashKey, byte[] password){

        String key = Base64.getEncoder().encodeToString(hashKey);


        // unknown domain
        if (mapPasswords.containsKey(key)) {
            mapPasswords.replace(key, new UserData(null,null, null,null,null,password,null, null));

        } else {
            mapPasswords.put(key, new UserData(null,null, null,null,null,password,null, null));
        }
    }

    public byte[] getPassword(byte[] hashKey) {

        String key = Base64.getEncoder().encodeToString(hashKey);

        UserData signatureAuthentication = mapPasswords.get(key);
        if(signatureAuthentication == null) {
            throw new InvalidArgumentsException();
        }
        return signatureAuthentication.password;
    }

	public void updateInfo(byte[]hashKey, byte[] password, UserData dataTransfer) {

        String key = Base64.getEncoder().encodeToString(hashKey);

        if (mapPasswords.containsKey(key)) {                    // unknown domain
            int ts = Crypto.byteArrayToLeInt(mapPasswords.get(key).wts);
            Integer wts = Crypto.byteArrayToLeInt(dataTransfer.wts);
            if (wts > ts)
                mapPasswords.replace(key, dataTransfer);
                 mapPasswords.replace(key, dataTransfer);

        } else {
            mapPasswords.put(key, dataTransfer);

        }
        saveOperation(dataTransfer);
        counter++;

    }
    public void saveOperation( UserData sign){
        String folder = System.getProperty("user.dir");

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(folder + File.separator + "DataUser"+ counter+".txt" );
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
            outputStream.writeObject(sign);
            outputStream.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.out.println("Error writing state to file");
        }
    }
    public int numberOfPasswords(){
        int count=0;
        for (UserData userX : mapPasswords.values()) {
            count++;
        }
        return count;
    }

    public  byte[] getTimestamp(byte[] hashKey) {

        String key = Base64.getEncoder().encodeToString(hashKey);

        UserData signatureAuthentication = mapPasswords.get(key);
        if(signatureAuthentication == null) {
            throw new InvalidArgumentsException();
        }
        return signatureAuthentication.wts;
    }
}
