package br.hol.crypto;

public class CryptoException extends Exception {

	private static final long serialVersionUID = 1L;

	public CryptoException() {
		super();
	}

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(String message, Throwable causeThrowable) {
		super(message, causeThrowable);
	}

	public CryptoException(Throwable causeThrowable) {
		super(causeThrowable);
	}

}
