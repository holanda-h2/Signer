package br.hol.signer;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.hol.signer.cades.CAdESChecker;
import br.hol.signer.cades.CAdESSigner;
import br.hol.signer.demoiselle.MyDriverTest;
import br.hol.signer.pdf.PDFChecker;
import br.hol.signer.pdf.PDFSecurity;
import br.hol.signer.pdf.PDFSigner;
import br.hol.signer.security.AESCrypto;
import br.hol.signer.security.KeyData;
import br.hol.signer.security.KeyProvider;
import br.hol.signer.security.PKCS11KeyProvider;
import br.hol.signer.security.PKCS12KeyProvider;
import br.hol.signer.xml.XAdESSigner;
import br.hol.signer.xml.XMLChecker;
import br.hol.signer.xml.XMLSigner;

public class SignerApp {

	private static Logger L = LoggerFactory.getLogger(SignerApp.class);

	private static XMLSigner xmlSigner = null;
	private static XAdESSigner xadesSigner = null;
	private static PDFSigner pdfSigner = null;
	private static CAdESSigner cadesSigner = null;

	private static XMLChecker xmlChecker = null;
	private static PDFChecker pdfChecker = null;
	private static CAdESChecker cadesChecker = null;

	private static KeyData createKeyData(String pin) {
		String pathToKeystore = "";
		String passphraseForKeystore = "";
		String passphraseForKey = pin;
		return new KeyData(pathToKeystore, passphraseForKeystore, passphraseForKey);
	}

	private static KeyData createKeyDataP12(String pathKey, String passKey, String pin) {
		String pathToKeystore = pathKey;
		String passphraseForKeystore = passKey;
		String passphraseForKey = pin;
		return new KeyData(pathToKeystore, passphraseForKeystore, passphraseForKey);
	}

	private static PKCS11KeyProvider createToken(String pin) {
		KeyData keyData = createKeyData(pin);
		return new PKCS11KeyProvider(keyData);
	}

	private static PKCS12KeyProvider createKeystore(String pathKey, String passKey, String pin)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException,
			IOException {
		KeyData keyData = createKeyDataP12(pathKey, passKey, pin);
		return new PKCS12KeyProvider(keyData);
	}

	private static void createPDFSigner(KeyProvider provider) throws Exception {
		pdfSigner = new PDFSigner(provider);
	}

	public static void createXMLSigner(KeyProvider provider) throws Exception {
		xmlSigner = new XMLSigner(provider);
	}

	public static void createXAdESSigner(KeyProvider provider) throws Exception {
		xadesSigner = new XAdESSigner(provider);
	}

	public static void createCAdESSigner(KeyProvider provider) throws Exception {
		cadesSigner = new CAdESSigner(provider);
	}

	public static void createXMLChecker() throws Exception {
		xmlChecker = new XMLChecker();
	}

	public static void createPDFChecker() throws Exception {
		pdfChecker = new PDFChecker();
	}

	public static void createCAdESChecker() throws Exception {
		cadesChecker = new CAdESChecker();
	}

	public static void main(String[] args) throws Exception {
		PropertyConfigurator.configure("log4j.properties");
		String fileName = "";
		String filePK12 = "";
		String passPK12 = "";
		String pin = "";
		String device = "";
		KeyProvider provider = null;

		if (args[0].equals("S") || args[0].equals("X") || args[0].equals("D") || args[0].equals("E")) {
			device = args[1];
			fileName = args[2];
			pin = AESCrypto.decrypt(PDFSecurity.KEY, args[3]);
			if (device.equals("T")) {
				provider = createToken(pin);
			} else {
				filePK12 = args[4];
				passPK12 = AESCrypto.decrypt(PDFSecurity.KEY, args[5]);
				L.info("fileName: " + fileName);
				L.info("device: " + device);
				L.info("filePK12: " + filePK12);
				provider = createKeystore(filePK12, passPK12, pin);
			}
		}

		L.info("START: " + args[0]);
		if (args[0].equals("S")) {
			createPDFSigner(provider);
			pdfSigner.signFiles(fileName);
		} else if (args[0].equals("C")) {
			fileName = args[1];
			createPDFChecker();
			pdfChecker.checkFile(fileName);
		} else if (args[0].equals("T")) {
			String path = MyDriverTest.detectDriver();
			System.out.print(path);
		} else if (args[0].equals("X")) {
			createXMLSigner(provider);
			xmlSigner.signFiles(fileName);
		} else if (args[0].equals("D")) {
			createXAdESSigner(provider);
			xadesSigner.signFiles(fileName);
		} else if (args[0].equals("E")) {
			createCAdESSigner(provider);
			cadesSigner.signFiles(fileName);
		} else if (args[0].equals("F")) {
			createCAdESChecker();
			fileName = args[1];
			String fileNameP7S = fileName.substring(0, fileName.lastIndexOf('.')) + ".p7s";
			cadesChecker.checkFile(fileName, fileNameP7S);
		} else if (args[0].equals("V")) {
			fileName = args[1];
			createXMLChecker();
			xmlChecker.checkFile(fileName);
		} else if (args[0].equals("P")) {
			String oldPassword = (2 <= args.length) ? args[2] : "";
			String newPassword = (3 <= args.length) ? args[3] : "";
			PDFSecurity.addPassword(args[1], oldPassword, newPassword);
		}
		L.info("END: " + args[0]);
	}
}
