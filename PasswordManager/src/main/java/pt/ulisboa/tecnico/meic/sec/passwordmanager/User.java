package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Hashtable;


public class User {
    private Key publicKey;
    private Hashtable<String, Hashtable<String, String>> domains;

    public User(Key publicKey){
        this.publicKey = publicKey;
        domains = new Hashtable<>();
    }

    public boolean isUserKey(Key key){
        return key.equals(this.publicKey);
    }

    public void updateInfo(byte[] domain, byte[] username, byte[] password){
        String domainString = new String (domain, StandardCharsets.UTF_8);
        String usernameString = new String (username, StandardCharsets.UTF_8);
        String passwordString = new String (password, StandardCharsets.UTF_8);

        Hashtable<String, String> usernames = domains.get(domainString);
        if (usernames == null){					// unknown domain
            usernames = new Hashtable<String, String>();
            usernames.put(usernameString, passwordString);
            domains.put(domainString, usernames);
        }
        else{									// known domain
            String pass = usernames.get(usernameString);
            if (pass == null){						// unknown username
                usernames.put(usernameString, passwordString);
            }
            else{									// known username
                usernames.replace(usernameString, passwordString);
            }
        }
    }

    public byte[] getPassword(byte[] domain, byte[] username) {
        String domainString = new String (domain, StandardCharsets.UTF_8);
        String usernameString = new String (username, StandardCharsets.UTF_8);
        Hashtable<String, String> usernames = domains.get(domainString);
        if(usernames == null) {
            throw new InvalidArgumentsException();
        }
        String password = usernames.get(usernameString);
        if (password == null) {
            throw new InvalidArgumentsException();
        }
        return password.getBytes(StandardCharsets.UTF_8);
    }
}
