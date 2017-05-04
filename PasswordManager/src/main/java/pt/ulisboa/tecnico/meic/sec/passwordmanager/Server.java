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

public class Server implements Serializable {

    /**
     * List users in the system
     */
    private ConcurrentHashMap<Key, User> users;
    private int registryPort;
    private int counter;
    private String path = System.getProperty("user.dir") + File.separator;


    public Server() throws RemoteException {
        users = new ConcurrentHashMap<Key, User>();
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

    public UserData get(Key publicKey, byte[] hashKey) throws RemoteException {
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

    public void put(Key publicKeySender, UserData transferData) {

        if (publicKeySender == null || transferData.hashDomainUser == null) {
            throw new InvalidArgumentsException();
        }
        if (users.containsKey(publicKeySender)) {

            users.get(publicKeySender).updateInfo(transferData.hashDomainUser, transferData);
            saveOperation(transferData);
            counter++;
            return;

        }
        throw new InvalidArgumentsException();
    }

    /**
     * Used for saving persistent data
     */
    public void setPort(int registryPort) {
        this.registryPort=registryPort;
        path=path+ registryPort + File.separator;
        File dir = new File(path);
        deleteDir(dir);
        dir.mkdirs();
    }

    public void saveOperation( UserData sign){

        try {

            String filename = path + "DataUser" + counter + ".txt";
            File file = new File(filename);

            FileOutputStream fileOutputStream = new FileOutputStream(file);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
            outputStream.writeObject(sign);
            outputStream.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.out.println("Error writing state to file");
        }
    }
    private  boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i<children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
        return dir.delete();
    }
}
