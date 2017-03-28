package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.math.BigInteger;
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
    public byte[] passwordIv;

    // constructor to serialize object
    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] domain, byte[] username, byte[] password, byte[] secretKey, byte[] randomIv, byte[] passwordIv) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.passwordIv = passwordIv;
    }

    public Message(byte[] challenge, byte[] domain, byte[] username, byte[] password){
        if(challenge != null){
            this.challenge = challenge;
        }
        else{
            this.challenge = null;
        }
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.passwordIv = null;
    }

    public Message(){
        this.publicKeySender = null;
        this.signature = this.challenge = this.domain = this.username = null;
        this.password = this.secretKey = this.randomIv = this.passwordIv = null;
    }

}
