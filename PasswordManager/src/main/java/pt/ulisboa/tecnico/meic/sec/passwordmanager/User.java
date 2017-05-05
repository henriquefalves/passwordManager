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
    protected Hashtable<String, LinkedList<UserData>> mapPasswords;

    public User(Key publicKey){
        this.publicKey = publicKey;
        mapPasswords = new Hashtable<>();
    }


    public void updateInfo(byte[]hashKey,  UserData dataTransfer) {
        String key = Base64.getEncoder().encodeToString(hashKey);
        if(ServerApplication.BYZANTINE_CODE==3){
            dataTransfer.password="invalidaPassword".getBytes();
        }
        if (mapPasswords.containsKey(key)) {
            LinkedList<UserData> history = mapPasswords.get(key);
            int lastWts = Crypto.byteArrayToInt(history.getLast().wts);
            int receivedWts = Crypto.byteArrayToInt(dataTransfer.wts);
            if (receivedWts > lastWts) {
                history.add(dataTransfer);
            }
            if(receivedWts == lastWts) {
                int lastRank = Crypto.byteArrayToInt(history.getLast().rank);
                int receivedRank = Crypto.byteArrayToInt(dataTransfer.rank);
                if(receivedRank > lastRank){
                    history.add(dataTransfer);
                }
            }
        } else {
            LinkedList<UserData> newHistory = new LinkedList<>();
            newHistory.add(dataTransfer);
            mapPasswords.put(key, newHistory);
        }
    }


    public UserData getUserData(byte[] hashKey) {
        String key = Base64.getEncoder().encodeToString(hashKey);
        LinkedList signatureAuthentication = mapPasswords.get(key);
        if(signatureAuthentication == null || signatureAuthentication.getLast() == null) {
            return new UserData();
        }
        return (UserData)signatureAuthentication.getLast();
    }


}
