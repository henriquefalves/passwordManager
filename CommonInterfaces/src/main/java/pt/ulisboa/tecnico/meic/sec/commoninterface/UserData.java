package pt.ulisboa.tecnico.meic.sec.commoninterface;

import java.io.Serializable;
import java.security.Key;
import java.security.PublicKey;

public class UserData implements Serializable {

	private static final long serialVersionUID = 1L;

	public byte[] signature;
    public byte[] hashDomainUser;
    public byte[] password;
    public byte[] rid;
	public byte[] wts;
	public byte[] hashCommunicationData;		// additional data to check signature

    public UserData(byte[] hashDomainUser, byte[] password, byte[] signature,
					byte[] rid, byte[] wts, byte[] hashCommunicationData) {
		this.signature = signature;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.rid = rid;
		this.wts = wts;
		this.hashCommunicationData = hashCommunicationData;
	}

	public UserData(byte[] hashDomainUser, byte[] password, byte[] wts) {
		this.signature = this.rid = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.wts = wts;
	}

	public UserData(byte[] hashDomainUser, byte[] password, byte[] wts, byte[] rid) {
		this.signature = this.rid = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.wts = wts;
		this.rid = rid;
	}

	public UserData(byte[] hashDomainUser, byte[] rid) {
		this.signature = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = null;
		this.wts = null;
		this.rid = rid;
	}

	public UserData() {
		this.signature = this.hashCommunicationData = null;
		this.hashDomainUser = this.password = null;
		this.wts = this.rid = null;
	}
}
