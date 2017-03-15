package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
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

    // constructor to serialize object
    public Message(Key publicKey, byte[] signature, byte[] seqNum, byte[] domain, byte[] username, byte[] password, byte[] secretKey, byte[] randomIv) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.sequenceNumber = seqNum;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
    }

    public Message(Key publicKey, byte[] signature, byte[] domain, byte[] username, byte[] password, byte[] secretKey, byte[] randomIv) {
        this.publicKey = publicKey;
        this.signature = signature;
     //   this.sequenceNumber = sequenceNumber;  // TODO
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
    }

    public Message(Key publicKey, byte[] signature, byte[] sequenceNumber, byte[] domain, byte[] username) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.sequenceNumber = sequenceNumber;
        this.domain = domain;
        this.username = username;
    }

    public Message(Key publicKey, byte[] signature, byte[] sequenceNumber, byte[] password) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.sequenceNumber = sequenceNumber;
        this.password = password;
    }

    public Message(Key publicKey, byte[] signature, byte[] sequenceNumber) {
        this.publicKey = publicKey;
        this.signature = signature;
        this.sequenceNumber = sequenceNumber;
    }

    public Message(){}
}
