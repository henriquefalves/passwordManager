package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.security.Key;

public class Message implements Serializable {

    public Key publicKeySender;
    public byte[] signature;
    public byte[] challenge;
    public byte[] domain;
    public byte[] username;
    public byte[] password;
    public byte[] secretKey;
    public byte[] randomIv;
    public int wts;
    public int rid;
    public UserData userData;

    // constructor to serialize object
    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] domain, byte[] username, byte[] password, byte[] secretKey, byte[] randomIv, int wts, int rid, UserData userData) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.wts = wts;
        this.rid = rid;
        this.userData = userData;
    }

    public Message(byte[] challenge, byte[] domain, byte[] username, byte[] password, int wts, int rid, UserData userData){
        this.challenge = challenge;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.wts = wts;
        this.rid = rid;
        this.userData = userData;
    }

    public Message(){
        this.publicKeySender = null;
        this.signature = this.challenge = this.domain = this.username = null;
        this.password = this.secretKey = this.randomIv = null;
    }
}
