package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.*;
import java.security.Key;
import java.util.Base64;
import java.util.Hashtable;
import java.util.LinkedList;


public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    private Key publicKey;
    /**
     * Key - [domain,username]
     * Value - History passwords
     */
    private Hashtable<String, LinkedList<UserData>> mapPasswords;
    private int counter;

    public User(Key publicKey){
        this.publicKey = publicKey;
        mapPasswords = new Hashtable<>();
    }

    public boolean isUserKey(Key key){
        return key.equals(this.publicKey);
    }



    public void updateInfo(byte[]hashKey,  UserData dataTransfer) {
        String key = Base64.getEncoder().encodeToString(hashKey);
        if (mapPasswords.containsKey(key)) {
            LinkedList<UserData> history = mapPasswords.get(key);
            int lastWts = Crypto.byteArrayToInt(history.getLast().wts);
            Integer wts = Crypto.byteArrayToInt(dataTransfer.wts);
            if (wts > lastWts) {
                history.add(dataTransfer);
            }
        } else {
            LinkedList<UserData> newHistory = new LinkedList<>();
            newHistory.add(dataTransfer);
            mapPasswords.put(key, newHistory);
        }
        saveOperation(dataTransfer);
        counter++;
    }

//    public byte[] getPassword(byte[] hashKey) {
//
//        String key = Base64.getEncoder().encodeToString(hashKey);
//
//        UserData signatureAuthentication = mapPasswords.get(key).getLast();
//        if(signatureAuthentication == null) {
//            throw new InvalidArgumentsException();
//        }
//        return signatureAuthentication.password;
//    }

    public UserData getUserData(byte[] hashKey) {

        String key = Base64.getEncoder().encodeToString(hashKey);

        LinkedList signatureAuthentication = mapPasswords.get(key);
        if(signatureAuthentication == null || signatureAuthentication.getLast() == null) {
            throw new InvalidArgumentsException();
        }
        return (UserData)signatureAuthentication.getLast();
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

}
