package br.hol.crypto;

public enum SecurityProvider {
	/** Sun */
	SUN("SUN"),

	/** Bouncy Castle */
	BOUNCY_CASTLE("BC"),

	/** Apple */
	APPLE("Apple"),

	/** Microsoft CAPI */
	MS_CAPI("SunMSCAPI");

	private String jce;

	SecurityProvider(String jce) {
		this.jce = jce;
	}

	public String jce() {
		return jce;
	}

}
