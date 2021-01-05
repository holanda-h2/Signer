package br.hol.crypto.keystore;

public enum KeyStoreType {

	JKS("JKS", true), JCEKS("JCEKS", true), PKCS12("PKCS12", true), BKS_V1("BKS-V1", true), BKS("BKS", true),
	UBER("UBER", true), KEYCHAIN("KeychainStore", false), MS_CAPI_PERSONAL("Windows-MY", false),
	MS_CAPI_ROOT("Windows-ROOT", false), PKCS11("PKCS11", false), BCFKS("BCFKS", true), UNKNOWN("UNKNOWN", false);

	private String jce;
	private boolean fileBased;

	KeyStoreType(String jce, boolean fileBased) {
		this.jce = jce;
		this.fileBased = fileBased;
	}

	public String jce() {
		return jce;
	}

	public boolean isFileBased() {
		return fileBased;
	}

	public boolean hasEntryPasswords() {
		return this != PKCS11 && this != MS_CAPI_PERSONAL;
	}

	public boolean hasExportablePrivateKeys() {
		return this != PKCS11 && this != MS_CAPI_PERSONAL;
	}

	public boolean supportsKeyEntries() {
		return this == JCEKS || this == BKS || this == BKS_V1 || this == UBER || this == BCFKS || this == PKCS12;
	}

	public static KeyStoreType resolveJce(String jce) {
		for (KeyStoreType keyStoreType : values()) {
			if (jce.equals(keyStoreType.jce())) {
				return keyStoreType;
			}
		}
		return UNKNOWN;
	}

	@Override
	public String toString() {
		return jce();
	}
}
