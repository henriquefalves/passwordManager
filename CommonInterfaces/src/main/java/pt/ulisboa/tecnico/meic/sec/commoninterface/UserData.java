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
	public byte[] hashCommunicationData;

    public UserData(byte[] hashDomainUser, byte[] password, byte[] signature,
					byte[] rid, byte[] wts, byte[] hashCommunicationData) {
//		super();
		this.signature = signature;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.rid = rid;
		this.wts = wts;
		this.hashCommunicationData = hashCommunicationData;
	}

	public UserData(byte[] hashDomainUser, byte[] password, byte[] wts) {
		super();
		this.signature = this.rid = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = password;
		this.wts = wts;
	}

	public UserData(byte[] hashDomainUser, byte[] rid) {
		super();
		this.signature = this.hashCommunicationData = null;
		this.hashDomainUser = hashDomainUser;
		this.password = null;
		this.wts = null;
		this.rid = rid;
	}
}
