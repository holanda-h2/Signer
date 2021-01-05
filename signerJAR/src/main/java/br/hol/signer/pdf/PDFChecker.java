package br.hol.signer.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.hol.signer.security.CertificateInfo;
import br.hol.signer.security.SignatureInfo;

public class PDFChecker {

	public static final SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");

	private static final Logger L = LoggerFactory.getLogger(PDFChecker.class);

	public PDFChecker() {

	}

	public boolean checkFile(String fileName) {
		boolean valid = false;

		List<SignatureInfo> l = null;
		try {
			l = PDFChecker.getPDFSignatureInfo(new FileInputStream(new File(fileName)));
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException | InvalidNameException | IOException e) {
			e.printStackTrace();
		}
		ObjectMapper mapper = new ObjectMapper();
		final DateFormat df = new SimpleDateFormat("yyyy-MM-dd' 'HH:mm:ss");
		mapper.setDateFormat(df);
		String jsonString = "";
		if (l.isEmpty()) {
			jsonString = "[{\"signatureVerified\": \"NUL\"}]";
		} else {
			try {
				jsonString = mapper.writeValueAsString(l);
				valid = true;
			} catch (JsonProcessingException e) {
				L.error("CheckFile: when generating JSON");
				e.printStackTrace();
			}
		}
		System.out.println(jsonString);
		return valid;
	}

	private static byte[] getbyteArray(InputStream is) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		byte[] buffer = new byte[1024];
		int len;
		while ((len = is.read(buffer)) > -1) {
			baos.write(buffer, 0, len);
		}
		baos.flush();

		return baos.toByteArray();
	}

	public static List<SignatureInfo> getPDFSignatureInfo(InputStream is)
			throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException, InvalidNameException {

		byte[] byteArray = getbyteArray(is);
		return getPDFSignatureInfo(byteArray);
	}

	public static List<SignatureInfo> getPDFSignatureInfo(byte[] byteArray)
			throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException, InvalidNameException {

		List<SignatureInfo> lpsi = new ArrayList<SignatureInfo>();

		try (PDDocument document = PDDocument.load(new ByteArrayInputStream(byteArray))) {
			for (PDSignature sig : document.getSignatureDictionaries()) {
				SignatureInfo psi = new SignatureInfo();
				lpsi.add(psi);

				COSDictionary sigDict = sig.getCOSObject();
				COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

				psi.reason = sig.getReason();
				psi.name = sig.getName();
				psi.signDate = sig.getSignDate().getTime();
				psi.subFilter = sig.getSubFilter();
				psi.contactInfo = sig.getContactInfo();
				psi.filter = sig.getFilter();
				psi.location = sig.getLocation();

				byte[] buf;
				buf = sig.getSignedContent(new ByteArrayInputStream(byteArray));

				int[] byteRange = sig.getByteRange();
				if (byteRange.length != 4) {
					L.error("Signature byteRange must have 4 items");
					throw new IOException("Signature byteRange must have 4 items");
				} else {
					long fileLen = byteArray.length;
					long rangeMax = byteRange[2] + (long) byteRange[3];

					int contentLen = sigDict.getString(COSName.CONTENTS).length() * 2 + 2;
					if (fileLen != rangeMax || byteRange[0] != 0 || byteRange[1] + contentLen != byteRange[2]) {
						psi.coversWholeDocument = false;
					} else {
						psi.coversWholeDocument = true;
					}
				}

				String subFilter = sig.getSubFilter();
				if (subFilter != null) {
					switch (subFilter) {
					case "adbe.pkcs7.detached":
						verifyPKCS7(buf, contents, sig, psi);
						break;
					case "adbe.pkcs7.sha1": {
						byte[] hash = MessageDigest.getInstance("SHA1").digest(buf);
						verifyPKCS7(hash, contents, sig, psi);
						break;
					}
					case "PBAD.PAdES": {
						verifyPKCS7(buf, contents, sig, psi);
						break;
					}
					case "adbe.x509.rsa_sha1": {
						psi.signatureVerified = "Unable to verify adbe.x509.rsa_sha1 subfilter";
						break;
					}
					default:
						L.error("unknown certificate type " + subFilter);
						throw new IOException("Unknown certificate type " + subFilter);

					}
				} else {
					L.error("missing subfilter for cert dictionary");
					throw new IOException("Missing subfilter for cert dictionary");
				}
			}
		} catch (CMSException | OperatorCreationException ex) {
			L.error("PDFSignatureInfo: with error");
			throw new IOException(ex);
		}

		return lpsi;
	}

	private static void verifyPKCS7(byte[] byteArray, COSString contents, PDSignature sig, SignatureInfo psi)
			throws CMSException, CertificateException, StoreException, OperatorCreationException,
			NoSuchAlgorithmException, NoSuchProviderException, InvalidNameException {

		CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
		CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());
		Store<?> certificatesStore = signedData.getCertificates();
		Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
		SignerInformation signerInformation = signers.iterator().next();
		Collection<?> matches = certificatesStore.getMatches(signerInformation.getSID());
		X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
		X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);

		CertificateInfo ci = new CertificateInfo();
		psi.certificateInfo = ci;
		ci.issuerDN = certFromSignedData.getIssuerDN().toString();
		ci.subjectDN = certFromSignedData.getSubjectDN().toString();

		ci.notValidAfter = certFromSignedData.getNotAfter();
		ci.notValidBefore = certFromSignedData.getNotBefore();

		ci.signAlgorithm = certFromSignedData.getSigAlgName();
		ci.serial = certFromSignedData.getSerialNumber().toString();

		LdapName ldapDN = new LdapName(ci.issuerDN);
		for (Rdn rdn : ldapDN.getRdns()) {
			ci.issuerOIDs.put(rdn.getType(), rdn.getValue().toString());
		}

		ldapDN = new LdapName(ci.subjectDN);
		for (Rdn rdn : ldapDN.getRdns()) {
			ci.subjectOIDs.put(rdn.getType(), rdn.getValue().toString());
		}

		certFromSignedData.checkValidity(sig.getSignDate().getTime());

		if (isSelfSigned(certFromSignedData)) {
			L.info("verifyPKCS7: Certificate is self-signed");
			psi.isSelfSigned = true;
		} else {
			L.info("verifyPKCS7: Certificate is not self-signed");
			psi.isSelfSigned = false;
		}

		if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certFromSignedData))) {
			L.info("verifyPKCS7: signature verified");
			psi.signatureVerified = "YES";
		} else {
			L.info("verifyPKCS7: signature verification failed");
			psi.signatureVerified = "NO";
		}
	}

	private static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException | InvalidKeyException sigEx) {
			L.error("isSelfSigned: return false");
			return false;
		}
	}

}
