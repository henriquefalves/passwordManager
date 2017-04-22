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
    public byte[] currentCommunicationData;     // communication data of current message what Server stores to check signature

    // constructor to serialize object
    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] secretKey,
                                    byte[] randomIv, UserData userData, byte[]currCommData) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.userData = userData;
        this.currentCommunicationData = currCommData;
    }

    public Message(Key publicKeySender, byte[] signature, byte[] challenge, byte[] secretKey,
                                                        byte[] randomIv, UserData userData) {
        this.publicKeySender = publicKeySender;
        this.signature = signature;
        this.challenge = challenge;
        this.secretKey = secretKey;
        this.randomIv = randomIv;
        this.userData = userData;
        this.currentCommunicationData = null;
    }

    public Message(byte[] challenge, UserData userData){
        this.challenge = challenge;
        this.userData = userData;
        this.publicKeySender = null;
        this.signature = null;
        this.secretKey = null;
        this.randomIv = null;
        this.currentCommunicationData = null;
    }

    public Message(){
        this.publicKeySender = null;
        this.signature = this.challenge  =  null;
        this.secretKey = this.randomIv = null;
        this.currentCommunicationData = null;
    }
}
