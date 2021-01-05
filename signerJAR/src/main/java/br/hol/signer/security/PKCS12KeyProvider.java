package br.hol.signer.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PKCS12KeyProvider extends KeyProvider {

	public static final String KEYSTORE_TYPE_PKCS12 = "pkcs12";

	private final KeyStore.PrivateKeyEntry keyEntry;
	private KeyStore keyStore;
	private KeyData keyData;

	public PKCS12KeyProvider(KeyData keyData) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableEntryException {

		this.keyData = keyData;
		this.keyStore = loadKeystore();
		this.keyEntry = loadKeyEntry();
	}

	private PrivateKey loadPrivateKey() {
		return keyEntry.getPrivateKey();
	}

	private PublicKey loadPublicKey() {
		return loadCertificate().getPublicKey();
	}

	private X509Certificate loadCertificate() {
		return (X509Certificate) keyEntry.getCertificate();
	}

	private KeyStore loadKeystore()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);

		FileInputStream keystoreStream = new FileInputStream(keyData.pathToKeystore);
		char[] passphrase = keyData.passphraseForKeystore;
		keyStore.load(keystoreStream, passphrase);
		return keyStore;
	}

	private KeyStore.PrivateKeyEntry loadKeyEntry()
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		char[] passphrase = keyData.passphraseForKey;
		String alias = keyStore.aliases().nextElement();
		return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(passphrase));
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public PrivateKey getPrivateKey() {
		return keyEntry.getPrivateKey();
	}

	public PublicKey getPublicKey() {
		return loadCertificate().getPublicKey();
	}

	public X509Certificate getCertificate() {
		return (X509Certificate) keyEntry.getCertificate();
	}

	@Override
	public Certificate[] getChain() {
		Certificate[] chain = new Certificate[1];
		chain[0] = this.getCertificate();
		return chain;
	}

	@Override
	public String getName() {
		return "";
	}

	@Override
	public String getCPF() {
		return "";
	}

}