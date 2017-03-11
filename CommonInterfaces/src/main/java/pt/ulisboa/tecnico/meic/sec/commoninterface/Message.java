package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.security.Key;

public class Message {

    private Key publicKey;
    private byte[] signature;
    private byte[] sequenceNumber;
    private byte[] domain;
    private byte[] username;
    private byte[] password;

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
