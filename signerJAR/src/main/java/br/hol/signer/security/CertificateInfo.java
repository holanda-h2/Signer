package br.hol.signer.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CertificateInfo {

	public String name;
	public String issuerDN;
	public String subjectDN;

	public Date notValidBefore;
	public Date notValidAfter;

	public String signAlgorithm;
	public String serial;

	public String email;
	public String cpf;
	public String birthDate;

	public Map<String, String> issuerOIDs = new HashMap<>();
	public Map<String, String> subjectOIDs = new HashMap<>();

}
