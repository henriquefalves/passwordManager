package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.Key;

public class Message implements Serializable {

    public Key publicKey;
    public byte[] signature;
    public byte[] sequenceNumber;
    public byte[] domain;
    public byte[] username;
    public byte[] password;
    public byte[] secretKey;
    public byte[] randomIv;
    public byte[] passwordIv;

    // constructor to serialize object
    public Message(Key publicKey, byte[] signature, byte[] seqNum, byte[] domain, byte[] username, byte[] password, byte[] secretKey, byte[] randomIv, byte[] passwordIv) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.sequenceNumber = seqNum;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.passwordIv = passwordIv;
    }

    public Message(BigInteger seqNum, byte[] domain, byte[] username, byte[] password){
        if(seqNum != null){
            this.sequenceNumber = seqNum.toByteArray();
        }
        else{
            this.sequenceNumber = null;
        }
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.publicKey = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.passwordIv = null;
    }

    public Message(){
        this.publicKey = null;
        this.signature = this.sequenceNumber = this.domain = this.username = null;
        this.password = this.secretKey = this.randomIv = this.passwordIv = null;
    }

}
