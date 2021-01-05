package br.hol.signer.cades;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.io.IOUtils;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.hol.signer.Signer;
import br.hol.signer.security.KeyProvider;

public class CAdESSigner extends Signer {

	private KeyProvider token;

	protected PKCS7Signer signer;

	private static final Logger L = LoggerFactory.getLogger(CAdESSigner.class);

	public CAdESSigner(KeyProvider provider) {
		this.token = provider;
		this.initSigner();
	}

	private void initSigner() {
		this.signer = PKCS7Factory.getInstance().factory();
		Policies signaturePolicy = PolicyFactory.Policies.AD_RB_CADES_2_3;
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

	public void signFiles(String nameFile) throws NoSuchAlgorithmException, IOException {
		String[] parts = nameFile.split(";");
		for (String part : parts) {
			L.info("singFile: " + part);
			this.signWithHash(part);
		}
	}

	public void signWithHash(String inFileName) throws NoSuchAlgorithmException, IOException {
		L.info("sign: Início");

		File inFile = new File(inFileName);

		byte[] content = this.getContent(inFile);

		L.info("sign: prepare signature");

		L.info("sign: Hash");
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		byte[] hash = md.digest(content);

		byte[] sign = this.doHashSign(hash);

		File outFile = this.getOutFile(inFile);
		FileOutputStream os = new FileOutputStream(outFile);
		os.write(sign);
		os.flush();
		os.close();

		L.info("sign: sign");

		L.info("sign: OK");
	}

	public byte[] getContent(File inFile) {
		byte[] content = null;

		try {
			InputStream in = new FileInputStream(inFile);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			IOUtils.copy(in, out);
			content = out.toByteArray();
			in.close();
		} catch (IOException e) {
			L.error("getContent: with error");
			e.printStackTrace();
		}
		return content;
	}

	protected File getOutFile(File source) throws IOException {
		String path = source.getCanonicalPath();
		path = path.substring(0, path.lastIndexOf('.')) + ".p7s";
		return new File(path);
	}

}
