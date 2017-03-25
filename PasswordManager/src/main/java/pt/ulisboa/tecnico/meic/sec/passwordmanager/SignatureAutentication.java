package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import java.security.Key;
import java.security.PublicKey;

public class SignatureAutentication {

    public Key publicKeySender;
  
	public byte[] signature;
    public byte[] sequenceNumber;
    public byte[] domain;
    public byte[] username;
    public byte[] password;
    public byte[] randomIv;

	public SignatureAutentication(byte[] randomIv, Key publicKeySender, PublicKey myPublicKey, byte[] sequenceNumber,
			byte[] domain, byte[] username, byte[] password, byte[] signature) {
		super();
		this.publicKeySender = publicKeySender;
		this.signature = signature;
		this.sequenceNumber = sequenceNumber;
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.randomIv = randomIv;
	}
	
	public boolean verifySignature(){
		return false;
	}


}
