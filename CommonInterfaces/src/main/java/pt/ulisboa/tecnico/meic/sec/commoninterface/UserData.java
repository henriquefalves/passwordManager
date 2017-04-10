package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.security.Key;
import java.security.PublicKey;

public class UserData implements Serializable {

	private static final long serialVersionUID = 1L;

	public Key publicKeySender;
	public PublicKey publicKeyReceiver;
	public byte[] signature;
    public byte[] challenge;
    public byte[] domain;
    public byte[] username;
    public byte[] password;
    public byte[] randomIv;

	public UserData(byte[] randomIv, Key publicKeySender, PublicKey publicKeyReceiver, byte[] challenge,
								   byte[] domain, byte[] username, byte[] password, byte[] signature) {
		super();
		this.publicKeySender = publicKeySender;
		this.publicKeyReceiver = publicKeyReceiver;
		this.signature = signature;
		this.challenge = challenge;
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.randomIv = randomIv;
	}


	/**
	 * At anytime a server admin could check the validity of the stored password
	 */
	public boolean verifySignature(){
		//TODO
		return false;
	}


}
