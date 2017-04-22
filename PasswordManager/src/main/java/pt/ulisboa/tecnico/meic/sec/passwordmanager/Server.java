package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.ServerAPI;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.DuplicatePublicKeyException;
import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.io.*;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

public class Server implements ServerAPI, Serializable {

    private ConcurrentHashMap<Key, User> users;


    public Server() throws RemoteException {
        users = new ConcurrentHashMap<Key, User>();
        //importObjects();
    }

    public void register(Key publicKey) throws RemoteException {
        if (publicKey == null) {
            throw new InvalidArgumentsException();
        }
        if (users.containsKey(publicKey))
            throw new DuplicatePublicKeyException();

        User newUser = new User(publicKey);
        users.put(publicKey, newUser);
    }

    @Deprecated
    public void put(Key publicKey, byte[] hashKey, byte[] password) throws RemoteException {

        throw new RuntimeException();

    }

    public byte[] get(Key publicKey, byte[] hashKey) throws RemoteException {

        if (publicKey == null || hashKey == null ) {
            {
                throw new InvalidArgumentsException();
            }
        }
        if (users.containsKey(publicKey)) {
            byte[] password = users.get(publicKey).getPassword(hashKey);
            return password;
        }
        throw new InvalidArgumentsException();
    }

    public UserData newGet(Key publicKey, byte[] hashKey) throws RemoteException {
        if (publicKey == null || hashKey == null ) {
            {
                throw new InvalidArgumentsException();
            }
        }
        if (users.containsKey(publicKey)) {
            return users.get(publicKey).getUserData(hashKey);
        }
        throw new InvalidArgumentsException();
    }

    public byte[] put(Key publicKeySender, UserData transferData) {

        if (publicKeySender == null || transferData.hashDomainUser == null) {
            throw new InvalidArgumentsException();
        }
        if (users.containsKey(publicKeySender)) {

            users.get(publicKeySender).updateInfo(transferData.hashDomainUser, transferData);
            return transferData.wts;

        }
        throw new InvalidArgumentsException();
    }




//       we need this?

//    public void importObjects() {
//        String folder = System.getProperty("user.dir");
//        FileInputStream fi = null;
//        int counter = 0;
//        boolean exitsFiles = true;
//        while (exitsFiles) {
//            try {
//                fi = new FileInputStream(new File(folder + File.separator + "DataUser" + counter + ".txt"
//                ));
//                ObjectInputStream oi = new ObjectInputStream(fi);
//                UserData data = (UserData) oi.readObject();
//                oi.close();
//                fi.close();
//                if (users.containsKey(data.publicKeySender))
//                    users.get(data.publicKeySender).updateInfo(data.hashDomainUser, data.password, data);
//                else {
//                    users.put(data.publicKeySender, new User(data.publicKeySender));
//                    users.get(data.publicKeySender).updateInfo(data.hashDomainUser, data.password, data);
//                }
//                counter++;
//            } catch (FileNotFoundException e) {
//                exitsFiles = false;
//            } catch (IOException e) {
//                exitsFiles = false;
//            } catch (ClassNotFoundException e) {
//                exitsFiles = false;
//
//            }
//        }
//        System.out.println("LOADED " + counter + " Passwords");
//
//    }


}
