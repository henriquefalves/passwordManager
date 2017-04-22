package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.security.Key;

public class Message implements Serializable {

    public Key publicKeySender;
    public byte[] signature;
    public byte[] challenge;
    public byte[] secretKey;
    public byte[] randomIv;
    public UserData userData;

    // constructor to serialize object
    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] secretKey, byte[] randomIv, UserData userData) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.userData = userData;
    }

    public Message(UserData userData){
        this.challenge = null;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.userData = userData;
    }
    public Message(byte[] challenge){
        this.challenge = challenge;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.userData = null;
    }

    public Message(){
        this.publicKeySender = null;
        this.signature = this.challenge  =  null;
        this.secretKey = this.randomIv = null;
    }
}
