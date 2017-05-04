package pt.ulisboa.tecnico.meic.sec.passwordmanager;


import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.meic.sec.commoninterface.Crypto;
import pt.ulisboa.tecnico.meic.sec.commoninterface.UserData;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.Assert.assertEquals;

public class UserTest {

    private PublicKey clientPublic;
    private byte[] VALID_HASH_DOMAIN_USERNAME;
    private UserData newReceivedUserData;

    @Before
    public void setup()  {
        clientPublic = getValidClientPublicKey();
        VALID_HASH_DOMAIN_USERNAME = getValidHashDomainUsername("facebook.com","henrique");
    }


    private byte[] getValidHashDomainUsername(String domain, String username) {
        byte[] VALID_DOMAIN = domain.getBytes(StandardCharsets.UTF_8);
        byte[] VALID_USERNAME = username.getBytes(StandardCharsets.UTF_8);
        byte[] hashPreKey = Crypto.concatenateData(new byte[][]{VALID_DOMAIN, VALID_USERNAME});
        return Crypto.hashData(hashPreKey);

    }

    private PublicKey getValidClientPublicKey() {
        KeyPair clientKeyPair = ServerApplication.loadKeys("test.jks", "test", "ClientKeys", "12345");
        return clientKeyPair.getPublic();
    }


    @Test
    public void FirstUpdateInfo(){
        User user = new User(clientPublic);
        assertEquals(user.mapPasswords.isEmpty(), true);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,new UserData());
        assertEquals(1,user.mapPasswords.size());
    }
    @Test
    public void SecondUpdateInfoDifferentDomainUser(){
        User user = new User(clientPublic);
        assertEquals(user.mapPasswords.isEmpty(), true);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,new UserData());
        UserData secondUserData = new UserData();
        user.updateInfo(getValidHashDomainUsername("twitter", "henrique"),secondUserData);
        assertEquals(2,user.mapPasswords.size());
    }
    @Test
    public void SecondUpdateSmallerTimestampSameRank(){
        User user = new User(clientPublic);
        UserData firstUserData = new UserData();
        firstUserData.wts=Crypto.intToByteArray(3);
        firstUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,firstUserData);

        UserData secondUserData = new UserData();
        secondUserData.wts=Crypto.intToByteArray(1);
        secondUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,secondUserData);
        String key = Base64.getEncoder().encodeToString(VALID_HASH_DOMAIN_USERNAME);

        assertEquals(1, user.mapPasswords.get(key).size());
    }
    @Test
    public void SecondUpdateSameTimestampSameRank(){
        User user = new User(clientPublic);
        UserData newUserData = new UserData();
        newUserData.wts=Crypto.intToByteArray(1);
        newUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,newUserData);

        UserData secondUserData = new UserData();
        secondUserData.wts=Crypto.intToByteArray(1);
        secondUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,secondUserData);
        String key = Base64.getEncoder().encodeToString(VALID_HASH_DOMAIN_USERNAME);
        assertEquals(1,user.mapPasswords.get(key).size());
    }
    @Test
    public void SecondUpdateSameTimestampBiggerRank(){
        User user = new User(clientPublic);
        UserData newUserData = new UserData();
        newUserData.wts=Crypto.intToByteArray(3);
        newUserData.rank=Crypto.intToByteArray(2);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,newUserData);

        UserData secondUserData = new UserData();
        secondUserData.wts=Crypto.intToByteArray(3);
        secondUserData.rank=Crypto.intToByteArray(5);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,secondUserData);
        String key = Base64.getEncoder().encodeToString(VALID_HASH_DOMAIN_USERNAME);
        assertEquals(2,user.mapPasswords.get(key).size());
    }

    @Test
    public void SecondUpdateBiggerTimestamp(){
        User user = new User(clientPublic);
        UserData newUserData = new UserData();
        newUserData.wts=Crypto.intToByteArray(3);
        newUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,newUserData);

        UserData secondUserData = new UserData();
        secondUserData.wts=Crypto.intToByteArray(5);
        secondUserData.rank=Crypto.intToByteArray(1);
        user.updateInfo(VALID_HASH_DOMAIN_USERNAME,secondUserData);
        String key = Base64.getEncoder().encodeToString(VALID_HASH_DOMAIN_USERNAME);
        assertEquals(2,user.mapPasswords.get(key).size());
    }


}
