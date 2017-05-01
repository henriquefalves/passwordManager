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
	public byte[] ridToCheckSign;
	public byte[] wts;
	public byte[] rank;
	public byte[] hashCommunicationData;		// additional data to check signature

    public UserData(byte[] hashDomainUser, byte[] password, byte[] signature,
					byte[] rid, byte[] ridToCheckSign, byte[] wts, byte[] rank, byte[] hashCommunicationData) {
		this.signature = signature;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.rid = rid;
		this.ridToCheckSign = ridToCheckSign;
		this.wts = wts;
		this.rank = rank;
		this.hashCommunicationData = hashCommunicationData;
	}

//	public UserData(byte[] hashDomainUser, byte[] password, byte[] wts) {
//		this.signature = this.rid = this.hashCommunicationData = null;
//		this.hashDomainUser = hashDomainUser;
//		this.password = password;
//		this.wts = wts;
//	}

	public UserData(byte[] hashDomainUser, byte[] password, byte[] wts, byte[] rid, byte[] rank) {
		this.signature = this.rid = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.wts = wts;
		this.rid = rid;
		this.rank = rank;
		this.ridToCheckSign = null;
	}

	public UserData(byte[] hashDomainUser, byte[] rid, byte[] rank) {
		this.signature = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = null;
		this.wts = null;
		this.rid = rid;
		this.rank = rank;
		this.ridToCheckSign = null;
	}

	public UserData() {
		this.signature = this.hashCommunicationData = null;
		this.hashDomainUser = this.password = null;
		this.wts = this.rid = this.rank = null;
		this.ridToCheckSign = null;
	}
}
