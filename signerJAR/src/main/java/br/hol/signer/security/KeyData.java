package br.hol.signer.security;

public class KeyData {

	public final String pathToKeystore;
	public final char[] passphraseForKeystore;
	public final char[] passphraseForKey;

	public KeyData(String pathToKeystore, String passphraseForKeystore, String passphraseForKey) {
		this.pathToKeystore = pathToKeystore;
		this.passphraseForKeystore = passphraseForKeystore.toCharArray();
		this.passphraseForKey = passphraseForKey.toCharArray();
	}

}