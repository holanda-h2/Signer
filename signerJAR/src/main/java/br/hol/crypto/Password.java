
package br.hol.crypto;

public class Password {

	private char[] wrappedPassword;
	private boolean nulled;

	public Password(char[] password) {
		this.wrappedPassword = password;
		nulled = false;
	}

	public Password(Password password) {
		if (password.isNulled()) {
			nulled = true;
			wrappedPassword = new char[] { 0 };
		} else {
			char[] wrappedPwd = password.toCharArray();
			if (wrappedPwd != null) {
				this.wrappedPassword = new char[wrappedPwd.length];
				System.arraycopy(wrappedPwd, 0, this.wrappedPassword, 0, this.wrappedPassword.length);
			}
		}
	}

	public char[] toCharArray() throws IllegalStateException {
		if (nulled) {
			throw new IllegalStateException("Password is nulled.");
		}
		return wrappedPassword;
	}

	public byte[] toByteArray() throws IllegalStateException {
		if (nulled) {
			throw new IllegalStateException("Password is nulled.");
		}
		if (wrappedPassword == null) {
			return null;
		}

		byte[] passwordBytes = new byte[wrappedPassword.length];

		for (int i = 0; i < wrappedPassword.length; i++) {
			passwordBytes[i] = (byte) wrappedPassword[i];
		}

		return passwordBytes;
	}

	public void nullPassword() {
		if (wrappedPassword == null) {
			return;
		}
		for (int i = 0; i < wrappedPassword.length; i++) {
			wrappedPassword[i] = 0;
		}
		nulled = true;
	}

	public boolean isNulled() {
		return nulled;
	}

	public boolean isEmpty() {
		return wrappedPassword.length == 0;
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}

		if (!(object instanceof Password)) {
			return false;
		}

		Password password = (Password) object;

		if (password.wrappedPassword == null) {
			return wrappedPassword == null;
		}

		if (wrappedPassword.length != password.wrappedPassword.length) {
			return false;
		}

		for (int i = 0; i < wrappedPassword.length; i++) {
			if (wrappedPassword[i] != password.wrappedPassword[i]) {
				return false;
			}
		}

		return true;
	}

	@Override
	protected void finalize() throws Throwable {
		super.finalize();
		nullPassword();
	}

}
