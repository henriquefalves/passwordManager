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
    private int registryPort;

    public User(Key publicKey){
        this.publicKey = publicKey;
        mapPasswords = new Hashtable<>();
    }

    public boolean isUserKey(Key key){
        return key.equals(this.publicKey);
    }


//    Ver. before AR N to N
//    public void updateInfo(byte[]hashKey,  UserData dataTransfer) {
//        String key = Base64.getEncoder().encodeToString(hashKey);
//        if (mapPasswords.containsKey(key)) {
//            LinkedList<UserData> history = mapPasswords.get(key);
//            int lastWts = Crypto.byteArrayToInt(history.getLast().wts);
//            Integer wts = Crypto.byteArrayToInt(dataTransfer.wts);
//            if (wts > lastWts) {
//                history.add(dataTransfer);
//            }
//        } else {
//            LinkedList<UserData> newHistory = new LinkedList<>();
//            newHistory.add(dataTransfer);
//            mapPasswords.put(key, newHistory);
//        }
//        saveOperation(dataTransfer);
//        counter++;
//    }

    public void updateInfo(byte[]hashKey,  UserData dataTransfer) {
        String key = Base64.getEncoder().encodeToString(hashKey);
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

        LinkedList userDataList = mapPasswords.get(key);
        if(userDataList == null) {
            LinkedList<UserData> newHistory = new LinkedList<>();
            UserData newUSerData = new UserData();
            newUSerData.wts = Crypto.intToByteArray(0);
            newUSerData.rank = Crypto.intToByteArray(0);
            newHistory.add(newUSerData);
            mapPasswords.put(key, newHistory);
            System.out.println("User-getUserData: Creating new User Data");
            return newUSerData;
        }
        return (UserData)userDataList.getLast();
    }

//    Ver. before AR N to N
//    public UserData getUserData(byte[] hashKey) {
//
//        String key = Base64.getEncoder().encodeToString(hashKey);
//
//        LinkedList signatureAuthentication = mapPasswords.get(key);
//        if(signatureAuthentication == null || signatureAuthentication.getLast() == null) {
//            throw new InvalidArgumentsException();
//        }
//        return (UserData)signatureAuthentication.getLast();
//    }



}
