package br.hol.signer.xml;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.hol.signer.SignatureNotFound;
import br.hol.signer.security.CertificateInfo;
import br.hol.signer.security.SignatureInfo;

public class XMLChecker {

	private static final String Mechanism_Type_Dom = "DOM";
	protected final XMLSignatureFactory factory = XMLSignatureFactory.getInstance(Mechanism_Type_Dom);

	public XMLChecker() {
	}

	public boolean checkFile(String pathToDocument) throws SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException, InvalidNameException {
		Document document = loadDocument(pathToDocument);
		return validateDocumentWithKey(document);
	}

	private boolean validateDocumentWithKey(Document document)
			throws MarshalException, XMLSignatureException, InvalidNameException {
		Node item = findSignatureElement(document);

		DOMValidateContext validateContext = new DOMValidateContext(new KeyValueKeySelector(), item);

		XMLSignature signature = factory.unmarshalXMLSignature(validateContext);

		boolean isValidate = signature.validate(validateContext);

		List<SignatureInfo> lpsi = new ArrayList<SignatureInfo>();

		List<?> list = signature.getKeyInfo().getContent();

		for (int i = 0; i < list.size(); i++) {

			XMLStructure xmlStructure = (XMLStructure) list.get(i);
			if (xmlStructure instanceof X509Data) {

				SignatureInfo psi = new SignatureInfo();
				lpsi.add(psi);
				CertificateInfo ci = new CertificateInfo();
				psi.certificateInfo = ci;

				if (isValidate) {
					psi.signatureVerified = "YES";
				} else {
					psi.signatureVerified = "NO";
				}

				PublicKey pk = null;
				X509Data x = (X509Data) xmlStructure;
				List<?> l = ((X509Data) xmlStructure).getContent();

				for (int j = 0; j < l.size(); j++) {
					if (l.size() > 0 && l.get(j) instanceof X509Certificate) {
						X509Certificate cert = (X509Certificate) l.get(j);

						ci.issuerDN = cert.getIssuerDN().getName();
						ci.subjectDN = cert.getSubjectDN().getName();
						ci.notValidBefore = cert.getNotBefore();
						ci.notValidAfter = cert.getNotAfter();
						ci.serial = cert.getSerialNumber().toString();
						ci.signAlgorithm = cert.getSigAlgName();

						LdapName ldapDN = new LdapName(ci.issuerDN);
						for (Rdn rdn : ldapDN.getRdns()) {
							ci.issuerOIDs.put(rdn.getType(), rdn.getValue().toString());
						}

						ldapDN = new LdapName(ci.subjectDN);
						for (Rdn rdn : ldapDN.getRdns()) {
							ci.subjectOIDs.put(rdn.getType(), rdn.getValue().toString());
						}

						pk = cert.getPublicKey();

					}
					if (l.size() > 0 && l.get(j) instanceof X509IssuerSerial) {
						X509IssuerSerial crl = (X509IssuerSerial) l.get(j);
					}
				}
			}

		}

		ObjectMapper mapper = new ObjectMapper();
		final DateFormat df = new SimpleDateFormat("yyyy-MM-dd' 'HH:mm:ss");
		mapper.setDateFormat(df);
		String jsonString = "";
		try {
			jsonString = mapper.writeValueAsString(lpsi);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}

		if (!isValidate) {
			jsonString = "[{\"signatureVerified\": \"NUL\"}]";
		}

		System.out.println(jsonString);

		return isValidate;
	}

	private Document loadDocument(String pathToDocument)
			throws SAXException, IOException, ParserConfigurationException {
		return new DocumentReader(pathToDocument).loadDocument();
	}

	private Node findSignatureElement(Document document) {
		NodeList nodeList = document.getElementsByTagNameNS(XMLNS, "Signature");
		if (nodeList.getLength() == 0) {
			throw new SignatureNotFound();
		}
		return nodeList.item(0);
	}

}