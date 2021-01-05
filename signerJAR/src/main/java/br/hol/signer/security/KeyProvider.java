package br.hol.signer.security;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public abstract class KeyProvider {

	public abstract KeyStore getKeyStore();

	public abstract PrivateKey getPrivateKey();

	public abstract PublicKey getPublicKey();

	public abstract X509Certificate getCertificate();

	public abstract Certificate[] getChain();

	public abstract String getName();

	public abstract String getCPF();

}
