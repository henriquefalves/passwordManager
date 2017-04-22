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
    public byte[] hashDomainUser;
    public byte[] password;
    public byte[] randomIv;
    public byte[] timestamp;

    public UserData(byte[] randomIv, Key publicKeySender, PublicKey publicKeyReceiver, byte[] challenge,
					byte[] hashDomainUser, byte[] password,
					byte[] signature, byte[] timestamp) {
		super();
		this.publicKeySender = publicKeySender;
		this.publicKeyReceiver = publicKeyReceiver;
		this.signature = signature;
		this.challenge = challenge;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.randomIv = randomIv;
		this.timestamp = timestamp;
	}
}
