package br.hol.signer.pdf;

import java.io.File;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.hol.signer.Signer;
import br.hol.signer.security.KeyProvider;

public class PDFSigner extends Signer {

	private Signature signature;

	private KeyProvider token;

	protected PKCS7Signer signer;

	private static final Logger L = LoggerFactory.getLogger(PDFSigner.class);

	public PDFSigner(KeyProvider provider) {
		this.token = provider;
		this.initSigner();
	}

	private void initSigner() {
		this.signer = PKCS7Factory.getInstance().factory();
		Policies signaturePolicy = PolicyFactory.Policies.AD_RB_PADES_1_1;
		this.signer.setSignaturePolicy(signaturePolicy);

		this.signer.setPrivateKey(this.token.getPrivateKey());

		this.signer.setCertificates(this.token.getChain());

		this.signer.setProvider(this.token.getKeyStore().getProvider());
		this.signer.setAlgorithm(this.getAlgorithm());

	}

	private SignerAlgorithmEnum getAlgorithm() {
		return SignerAlgorithmEnum.SHA256withRSA;
	}

	private byte[] doAttachedSign(byte[] content) {
		byte[] signature = this.signer.doAttachedSign(content);
		return signature;
	}

	private byte[] doHashSign(byte[] hash) {
		byte[] signature = this.signer.doHashSign(hash);
		return signature;
	}

	public void signFiles(String nameFile) {
		String[] parts = nameFile.split(";");
		for (String part : parts) {
			L.info("singFile: " + part);
			this.signWithHash(part);
		}
	}

	public void signWithHash(String inFileName) {
		L.info("sign: START");

		File inFile = new File(inFileName);
		this.signature = new Signature(inFile, this.token.getName(), this.token.getCPF());

		L.info("sign: PREPARE SIGNATURE");
		this.signature.prepare();

		L.info("sign: HASH");
		byte[] hash = this.signature.hash("SHA-256");

		byte[] sign = this.doHashSign(hash);

		L.info("sign: SIGN");
		this.signature.sign(sign);
		L.info("sign: OK");
	}

	public void signWithContent(String inFileName) {
		L.info("sign: START");

		File inFile = new File(inFileName);
		this.signature = new Signature(inFile, this.token.getName(), this.token.getCPF());

		L.info("sign: PREPARE SIGNATURE");
		this.signature.prepare();

		L.info("sign: HASH");
		byte[] content = this.signature.getContent();

		byte[] sign = this.doAttachedSign(content);

		L.info("sign: SIGN");
		this.signature.sign(sign);
		L.info("sign: OK");
	}

}
