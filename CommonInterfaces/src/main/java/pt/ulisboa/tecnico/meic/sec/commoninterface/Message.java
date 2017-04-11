package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.security.Key;

public class Message implements Serializable {

    public Key publicKeySender;
    public byte[] signature;
    public byte[] challenge;
    public byte[] hashKey;
    public byte[] password;
    public byte[] secretKey;
    public byte[] randomIv;
    public byte[] wts;
    public byte[] rid;
    public UserData userData;

    // constructor to serialize object
    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] hashKey, byte[] password, byte[] secretKey, byte[] randomIv,  byte[] wts,  byte[] rid, UserData userData) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.hashKey = hashKey;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.wts = wts;
        this.rid = rid;
        this.userData = userData;
    }

    public Message(byte[] challenge, byte[] hashKey, byte[] password,  byte[] wts,  byte[] rid, UserData userData){
        this.challenge = challenge;
        this.password = password;
        this.hashKey= hashKey;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.wts = wts;
        this.rid = rid;
        this.userData = userData;
    }
    public Message(byte[] challenge, byte[] hashKey,  byte[] password){
        this.challenge = challenge;
        this.password = password;
        this.hashKey=hashKey;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.userData = userData;
    }

    public Message(){
        this.publicKeySender = null;
        this.signature = this.challenge = this.hashKey =  null;
        this.password = this.secretKey = this.randomIv = null;
    }
}
