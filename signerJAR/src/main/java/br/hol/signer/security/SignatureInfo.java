package br.hol.signer.security;

import java.util.Date;

public class SignatureInfo {

	public String reason;
	public String name;
	public String subFilter;
	public String filter;
	public String contactInfo;
	public String location;

	public Date signDate;

	public boolean coversWholeDocument;
	public boolean isSelfSigned;

	public String signatureVerified;

	public CertificateInfo certificateInfo;

}
