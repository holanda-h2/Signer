package br.hol.signer.pdf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Signature {

	private static final Long SEED = 182959L;

	private File inFile;
	private File outFile;

	private PDDocument document;
	private PDSignature signature;

	private PDVisibleSignDesigner design;
	private PDVisibleSigProperties props;
	private SignatureOptions options;
	private ExternalSigningSupport externalSigningSupport;

	private Stamp stamp;
	private String name;
	private String cpf;

	private static final Logger L = LoggerFactory.getLogger(Signature.class);

	public Signature(File inFile) {
		this.inFile = inFile;
	}

	public Signature(File inFile, String name, String cpf) {
		this.inFile = inFile;
		this.name = name;
		this.cpf = cpf;
		this.init();
	}

	private void init() {
		this.signature = new PDSignature();
		this.signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		this.signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		this.signature.setName(this.name + ":" + this.cpf);
		InetAddress localhost = null;
		try {
			localhost = InetAddress.getLocalHost();
		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		}

		this.signature.setLocation(localhost.getHostAddress().trim());
		this.signature.setReason("Atendimento ao Decreto Nº 8.539, de 8 de outubro de 2015");
		Calendar data = Calendar.getInstance();
		this.signature.setSignDate(data);

		try {
			this.document = PDDocument.load(this.inFile);
		} catch (IOException e) {
			L.error("init: with error");
			e.printStackTrace();
		}
		this.initStamp();
	}

	public void loadDocument() {
		try {
			this.document = PDDocument.load(this.inFile);
			this.signature = this.document.getLastSignatureDictionary();
		} catch (IOException e) {
			L.error("loadDocument: with error");
			e.printStackTrace();
		}
	}

	private void initStamp() {
		this.stamp = new Stamp(this.name, this.cpf);
		InputStream imagem = null;
		try {
			imagem = new FileInputStream(this.stamp.getFile());
		} catch (FileNotFoundException e) {
			L.error("initStamp: stamp file error");
			e.printStackTrace();
		}
		int pageNumber = this.document.getNumberOfPages();

		int xi = 0;
		try {
			xi = this.document.getSignatureDictionaries().size();
		} catch (IOException e1) {
			L.error("initStamp: signature dictionaries");
			e1.printStackTrace();
		}

		float x = 400 - (190 * (xi % 3));
		float y = 780 - (40 * (int) (xi / 3));
		float zoomPercent = -70;

		try {
			this.design = new PDVisibleSignDesigner(this.document, imagem, pageNumber);
		} catch (IOException e) {
			L.error("initStamp: sign designer");
			e.printStackTrace();
		}
		this.design.xAxis(x).yAxis(y).zoom(zoomPercent).adjustForRotation();

		this.props = new PDVisibleSigProperties().signerName(this.signature.getName())
				.signerLocation(this.signature.getLocation()).signatureReason(this.signature.getReason())
				.preferredSize(0).page(pageNumber).visualSignEnabled(true).setPdVisibleSignature(this.design);
		this.buildOptions();
	}

	private void buildOptions() {
		try {
			this.props.buildSignature();
			this.options = new SignatureOptions();
			this.options.setVisualSignature(this.props.getVisibleSignature());
		} catch (IOException e) {
			L.error("buildOptions: with error");
			e.printStackTrace();
		}
		this.options.setPage(this.props.getPage() - 1);
	}

	protected File getOutFile(File source) throws IOException {
		String path = source.getCanonicalPath();
		path = path.substring(0, path.lastIndexOf('.')) + "-signed.pdf";
		return new File(path);
	}

	public void prepare() {
		this.document.setDocumentId(SEED);
		try {
			this.document.addSignature(this.signature, this.options);
			this.outFile = this.getOutFile(this.inFile);
			this.externalSigningSupport = this.document
					.saveIncrementalForExternalSigning(new FileOutputStream(this.outFile));
		} catch (IOException e) {
			L.error("prepare: with error");
			e.printStackTrace();
		}
	}

	public byte[] getContent() {
		byte[] content = null;

		try {
			InputStream in = this.externalSigningSupport.getContent();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			IOUtils.copy(in, out);
			content = out.toByteArray();
			in.close();
		} catch (IOException e) {
			L.error("getContent: with error");
			e.printStackTrace();
		}
		return content;
	}

	public byte[] hash(String algorithm) {
		byte[] content = this.getContent();
		byte[] hash = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(content);
			hash = md.digest();
		} catch (NoSuchAlgorithmException e) {
			L.error("hash: with error");
			e.printStackTrace();
		}
		return hash;
	}

	public void sign(byte[] sign) {
		try {
			this.externalSigningSupport.setSignature(sign);
			this.document.close();
		} catch (IOException e) {
			L.error("sign: with error");
			e.printStackTrace();
		}
	}

	public File getOutFile() {
		return this.outFile;
	}

}
