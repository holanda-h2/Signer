package br.hol.signer.xml;

import static java.util.Collections.singletonList;
import static javax.xml.crypto.dsig.CanonicalizationMethod.INCLUSIVE;
import static javax.xml.crypto.dsig.SignatureMethod.RSA_SHA1;
import static javax.xml.crypto.dsig.Transform.ENVELOPED;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import br.hol.signer.Signer;
import br.hol.signer.security.KeyProvider;

public class XMLSigner extends Signer {

	private static final String MECHANISM_TYPE_DOM = "DOM";
	protected final XMLSignatureFactory factory = XMLSignatureFactory.getInstance(MECHANISM_TYPE_DOM);

	private static final String ENTIRE_DOCUMENT = "";

	private KeyProvider provider;

	public XMLSigner(KeyProvider provider) throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException, CertificateException {
		this.provider = provider;
	}

	private KeyInfo loadKeyInfo() {
		X509Certificate certificate = this.provider.getCertificate();
		return createKeyInfoFactory(certificate);
	}

	private KeyInfo createKeyInfoFactory(X509Certificate certificate) {
		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		List<Serializable> x509Content = new ArrayList<Serializable>();
		x509Content.add(certificate.getSubjectX500Principal().getName());
		x509Content.add(certificate);
		X509Data data = keyInfoFactory.newX509Data(x509Content);
		return keyInfoFactory.newKeyInfo(singletonList(data));
	}

	private void sign(Document document, PrivateKey privateKey, SignedInfo signedInfo, KeyInfo keyInfo)
			throws MarshalException, XMLSignatureException {
		DOMSignContext signContext = new DOMSignContext(privateKey, document.getDocumentElement());
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
		signature.sign(signContext);
	}

	private SignedInfo createSignature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
		Transform transform = factory.newTransform(ENVELOPED, (TransformParameterSpec) null);
		Reference reference = factory.newReference(ENTIRE_DOCUMENT, digestMethod, singletonList(transform), null, null);
		SignatureMethod signatureMethod = factory.newSignatureMethod(RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(INCLUSIVE,
				(C14NMethodParameterSpec) null);
		return factory.newSignedInfo(canonicalizationMethod, signatureMethod, singletonList(reference));
	}

	public void signFiles(String nameFile) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			KeyStoreException, UnrecoverableEntryException, CertificateException, IOException,
			ParserConfigurationException, SAXException, MarshalException, XMLSignatureException, TransformerException {

		String[] parts = nameFile.split(";");
		for (String part : parts) {
			this.signWithHash(part);
		}
	}

	public void signWithHash(String pathToUnsignedDocument)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, IOException,
			UnrecoverableEntryException, CertificateException, ParserConfigurationException, SAXException,
			MarshalException, XMLSignatureException, TransformerException {
		Document document = new DocumentReader(pathToUnsignedDocument).loadDocument();
		SignedInfo signedInfo = createSignature();
		KeyInfo keyInfo = this.loadKeyInfo();
		PrivateKey privateKey = provider.getPrivateKey();

		this.sign(document, privateKey, signedInfo, keyInfo);

		String pathToSignedDocument = pathToUnsignedDocument.substring(0, pathToUnsignedDocument.lastIndexOf('.'))
				+ "-signed.xml";

		new DocumentWriter(pathToSignedDocument).writeDocument(document);
	}

}