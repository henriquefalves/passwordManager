package pt.ulisboa.tecnico.meic.sec.passwordmanager;

import java.security.Key;
import java.security.PublicKey;

public class SignatureAutentication {

    public Key publicKeySender;

    // TODO miss public keys (sender, receiver)
	public byte[] signature;
    public byte[] challenge;
    public byte[] domain;
    public byte[] username;
    public byte[] password;
    public byte[] randomIv;

	public SignatureAutentication(byte[] randomIv, Key publicKeySender, PublicKey myPublicKey, byte[] challenge,
			byte[] domain, byte[] username, byte[] password, byte[] signature) {
		super();
		this.publicKeySender = publicKeySender;
		this.signature = signature;
		this.challenge = challenge;
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.randomIv = randomIv;
	}
	
	public boolean verifySignature(){
		return false;
	}


}
