package br.hol.signer.cades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBRCertificatePF;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.hol.signer.security.CertificateInfo;
import br.hol.signer.security.SignatureInfo;

public class CAdESChecker {

	private static final Logger L = LoggerFactory.getLogger(CAdESChecker.class);

	public boolean checkFile(String fileName, String signatureFileName) throws IOException, InvalidNameException {
		boolean valid = false;

		byte[] fileToVerify = readContent(fileName);
		byte[] signatureFile = readContent(signatureFileName);

		org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker checker = new org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker();

		L.info("Performing the signature validation");
		List<SignatureInformations> signaturesInfo = checker.checkDetachedSignature(fileToVerify, signatureFile);

		List<SignatureInfo> lpsi = new ArrayList<SignatureInfo>();

		if (signaturesInfo != null) {
			L.info("The signature has been validated.");
			for (SignatureInformations si : signaturesInfo) {

				SignatureInfo psi = new SignatureInfo();
				lpsi.add(psi);

				psi.signDate = si.getSignDate();
				CertificateInfo ci = new CertificateInfo();
				psi.certificateInfo = ci;

				for (X509Certificate cert : si.getChain()) {
					BasicCertificate certificate = new BasicCertificate(cert);
					if (!certificate.isCACertificate()) {
						this.updateCertificateInfoWithBasic(ci, certificate);
					}
				}
				for (String valErr : si.getValidatorErrors()) {
					L.error(valErr);
				}
				if (si.getSignaturePolicy() != null) {
					this.updateCertificateInfoWithPolicy(ci, si.getSignaturePolicy());
				}

				LdapName ldapDN = new LdapName(ci.issuerDN);
				for (Rdn rdn : ldapDN.getRdns()) {
					ci.issuerOIDs.put(rdn.getType(), rdn.getValue().toString());
				}

				ldapDN = new LdapName(ci.subjectDN);
				for (Rdn rdn : ldapDN.getRdns()) {
					ci.subjectOIDs.put(rdn.getType(), rdn.getValue().toString());
				}

				psi.signatureVerified = "YES";

			}
			valid = true;

			ObjectMapper mapper = new ObjectMapper();
			final DateFormat df = new SimpleDateFormat("yyyy-MM-dd' 'HH:mm:ss");
			mapper.setDateFormat(df);
			String jsonString = "";
			try {
				jsonString = mapper.writeValueAsString(lpsi);
			} catch (JsonProcessingException e) {
				L.error("checkFile: JSON error");
				e.printStackTrace();
			}
			// }
			System.out.println(jsonString);

		} else {
			String jsonString = "[{\"signatureVerified\": \"NUL\"}]";
			System.out.println(jsonString);
			L.info("The signature has been invalidated!");
		}

		return valid;
	}

	private byte[] readContent(String parmFile) {
		byte[] result = null;
		try {
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}

	private void updateCertificateInfoWithBasic(CertificateInfo ci, BasicCertificate bc) throws IOException {

		ci.name = bc.getName();
		ci.issuerDN = bc.getCertificateIssuerDN().toString();
		ci.subjectDN = bc.getCertificateSubjectDN().toString();
		ci.serial = bc.getSerialNumber();
		ci.notValidBefore = bc.getBeforeDate();
		ci.notValidAfter = bc.getAfterDate();

		if (bc.hasCertificatePF()) {
			ICPBRCertificatePF tdPF = bc.getICPBRCertificatePF();
			ci.email = bc.getEmail();
			ci.cpf = tdPF.getCPF();
			ci.birthDate = tdPF.getBirthDate().substring(4, 8) + "-" + tdPF.getBirthDate().substring(2, 4) + "-"
					+ tdPF.getBirthDate().substring(0, 2);
		}

	}

	private void updateCertificateInfoWithPolicy(CertificateInfo ci, SignaturePolicy po) throws IOException {
		ci.signAlgorithm = SignerAlgorithmEnum
				.getSignerOIDAlgorithmHashEnum(po.getSignPolicyHashAlg().getAlgorithm().getValue()).getAlgorithm();
	}

}