package br.hol.signer.pdf;

import java.io.File;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.hol.signer.security.AESCrypto;

public class PDFSecurity {

	public static final String KEY = "ABCDEFGHIJKLMNOP";

	private static final Logger L = LoggerFactory.getLogger(PDFSecurity.class);

	public static void addPassword(String filePath, String oldPassword, String newPassword) {
		String oldPasswordAux = oldPassword;
		if (!oldPassword.isEmpty()) {
			String decrypt = AESCrypto.decrypt(PDFSecurity.KEY, oldPassword);
			oldPasswordAux = decrypt;
		}

		String newPasswordAux = newPassword;
		if (!newPassword.isEmpty()) {
			String decrypt = AESCrypto.decrypt(PDFSecurity.KEY, newPassword);
			newPasswordAux = decrypt;
		}

		PDDocument doc = null;
		try {
			doc = PDDocument.load(new File(filePath), oldPasswordAux);
		} catch (IOException e) {
			L.error("addPassword: in load");
			e.printStackTrace();
		}

		int keyLength = 128;

		AccessPermission ap = new AccessPermission();
		ap.setCanPrint(false);

		StandardProtectionPolicy spp = new StandardProtectionPolicy(newPasswordAux, newPasswordAux, ap);
		spp.setEncryptionKeyLength(keyLength);
		spp.setPermissions(ap);
		try {
			doc.protect(spp);
			doc.save(filePath);
			doc.close();
		} catch (IOException e) {
			L.error("addPassword: in save");
			e.printStackTrace();
		}
	}

}
