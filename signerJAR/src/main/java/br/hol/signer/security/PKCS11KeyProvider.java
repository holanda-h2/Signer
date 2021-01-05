package br.hol.signer.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.CertificateExtra;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.util.Proxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.hol.signer.demoiselle.MyConfiguration;
import br.hol.signer.demoiselle.MyKeyStoreLoaderFactory;

public class PKCS11KeyProvider extends KeyProvider {

	protected X509Certificate certificate;
	protected PrivateKey privateKey;
	protected Certificate[] chain;
	protected KeyStore keyStore;
	protected CallbackHandler callbackHandler;
	protected static char[] pin = "000000".toCharArray();
	private String driverPath = "c:/windows/system32/aetpkss1.dll";
	private ConfigurationInfo configInfo;
	private KeyData keyData;

	private static final Logger L = LoggerFactory.getLogger(PKCS11KeyProvider.class);

	public PKCS11KeyProvider(KeyData keyData) {
		this.keyData = keyData;
		this.initDriverPath();
		this.initConfiguration();
		this.initKeyStore(this.keyData.passphraseForKey);
		this.configToken();
	}

	private void initDriverPath() {
		try {
			if (this.configInfo == null) {
				String config = new String(Files.readAllBytes(Paths.get("configuration.json")), "UTF-8");
				this.configInfo = new ObjectMapper().readValue(config, ConfigurationInfo.class);
				this.driverPath = configInfo.driver;
				if (configInfo.proxy) {
					this.initProxy(configInfo);
				}
			}
		} catch (Exception e) {
			L.error("Starting the Signer. Path: " + this.driverPath);
			e.printStackTrace();
		}
	}

	private void initConfiguration() {
		MyConfiguration config = MyConfiguration.getInstance();
		config.addDriver("SmartCard", this.driverPath);
		MyConfiguration.setMSCAPI_ON(false);

		try {
			this.callbackHandler = getCallbackHandler();
		} catch (IOException e) {
			L.error("PIN with error");
			e.printStackTrace();
		}
	}

	void initProxy(ConfigurationInfo configInfo) throws Exception {
		Proxy.setProxyEndereco(configInfo.IP);
		Proxy.setProxyPorta(configInfo.port);
		Proxy.setProxySenha(configInfo.password);
		Proxy.setProxyUsuario(configInfo.user);
		Proxy.setProxy();
	}

	private void initKeyStore(char[] pin) {
		PKCS11KeyProvider.pin = pin;
		KeyStoreLoader loader = MyKeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(this.callbackHandler);
		this.keyStore = loader.getKeyStore();
	}

	private void configToken() {
		try {
			String alias = this.keyStore.aliases().nextElement();
			this.certificate = (X509Certificate) this.keyStore.getCertificate(alias);

			this.privateKey = (PrivateKey) this.keyStore.getKey(alias, null);

			this.chain = this.keyStore.getCertificateChain(alias);

		} catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
			L.error("Config with error");
			e.printStackTrace();
		}
	}

	public String getName() {
		BasicCertificate bc = new BasicCertificate(this.certificate);
		return bc.getName();
	}

	public String getCPF() {
		CertificateExtra ce = new CertificateExtra(this.certificate);
		return ce.getOID_2_16_76_1_3_1().getCPF();
	}

	private CallbackHandler getCallbackHandler() throws IOException {
		return new CallbackHandler() {
			public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
				for (Callback callback : callbacks) {
					if (callback instanceof PasswordCallback) {
						PasswordCallback pwd = ((PasswordCallback) callback);
						pwd.setPassword(PKCS11KeyProvider.pin);
					}
				}
			}
		};
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public Certificate[] getChain() {
		return chain;
	}

	public PublicKey getPublicKey() {
		return null;
	}

}
