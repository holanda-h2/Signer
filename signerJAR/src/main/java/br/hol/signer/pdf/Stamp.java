package br.hol.signer.pdf;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gui.ava.html.image.generator.HtmlImageGenerator;

public class Stamp {
	
	private String html;
	private String name;
	private String cpf;
	
	private static final Logger L = LoggerFactory.getLogger(Stamp.class);
	
	public Stamp(String name, String cpf) {
		this.name = name;
		this.cpf = cpf;
		this.init();
	}

	void init() {
		try {
			this.html = new String(Files.readAllBytes(Paths.get("stamp.html")), "UTF-8");
			this.html = this.html.replaceFirst("#NOME#", this.name);
			this.html = this.html.replaceFirst("#CPF#", this.cpf);
			
			DateFormat df = new SimpleDateFormat("dd-MM-yyyy' 'HH:mm:ss");
			String date = df.format(new Date());
			
			this.html = this.html.replaceFirst("#DATA#", date);
			
		} catch (IOException e) {
			L.error("init: with error");
			e.printStackTrace();
		}
	}
	
	public File getFile() {
		HtmlImageGenerator imageGenerator = new HtmlImageGenerator();
		imageGenerator.loadHtml(this.html);
		File img = null;
		try {
			img = File.createTempFile("./estampaXYZ", ".png");
		} catch (IOException e) {
			L.error("getFile: with error");
			e.printStackTrace();
		}
	    imageGenerator.saveAsImage(img);
	    return img;
	}
}
