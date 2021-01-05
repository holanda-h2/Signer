package br.hol.signer;

public class SignatureNotFound extends RuntimeException {

    public SignatureNotFound() {
        super("Cannot find Signature element.");
    }
}
