package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import pt.ulisboa.tecnico.meic.sec.commoninterface.exceptions.InvalidArgumentsException;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
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
        String domainString = Base64.getEncoder().encodeToString(domain);
        String usernameString = Base64.getEncoder().encodeToString(username);
        String passwordString = Base64.getEncoder().encodeToString(password);

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
    	String domainString = Base64.getEncoder().encodeToString(domain);
        String usernameString = Base64.getEncoder().encodeToString(username);
        Hashtable<String, String> usernames = domains.get(domainString);
        if(usernames == null) {
            throw new InvalidArgumentsException();
        }
        String password = usernames.get(usernameString);
        if (password == null) {
            throw new InvalidArgumentsException();
        }
        return Base64.getDecoder().decode(password);
    }
}
