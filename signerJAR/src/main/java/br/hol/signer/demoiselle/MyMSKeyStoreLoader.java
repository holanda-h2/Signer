package br.hol.signer.demoiselle;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyMSKeyStoreLoader implements KeyStoreLoader {

	private static final Logger logger = LoggerFactory.getLogger(MyMSKeyStoreLoader.class);
	protected static final String MS_PROVIDER = "SunMSCAPI";
	protected static final String MS_TYPE = "Windows-MY";
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	private CallbackHandler callback;

	@Override
	public KeyStore getKeyStore() {
		try {
			KeyStore result = KeyStore.getInstance(MyMSKeyStoreLoader.MS_TYPE, MyMSKeyStoreLoader.MS_PROVIDER);
			result.load(null, null);
			fixAliases(result);
			// verifica se tem acesso a chave, caso contrario pode ser CNG e acessarÃ¡ via
			// driver
			if (!this.verifyKeyEntry(result)) {
				MyDriverKeyStoreLoader driverKeyStoreLoader = new MyDriverKeyStoreLoader();
				result = driverKeyStoreLoader.getKeyStore();
			}
			return result;
		} catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException
				| CertificateException ex) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.load.mscapi"), ex);
		}
	}

	@Override
	public void setCallbackHandler(CallbackHandler callback) {
		this.setCallback(callback);
	}

	private boolean verifyKeyEntry(KeyStore ks) {

		boolean isKeyEntry = false;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				if (ks.isKeyEntry(alias)) {
					isKeyEntry = true;
				}

			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return isKeyEntry;
	}

	private void fixAliases(KeyStore keyStore) {
		Field field;
		KeyStoreSpi keyStoreVeritable;

		try {
			field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
			field.setAccessible(true);
			if (field.get(keyStoreVeritable) instanceof Map)
				return;

			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
				Collection<?> entries;
				String alias, hashCode;
				X509Certificate[] certificates;

				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				entries = (Collection<?>) field.get(keyStoreVeritable);

				for (Object entry : entries) {
					field = entry.getClass().getDeclaredField("certChain");
					field.setAccessible(true);
					certificates = (X509Certificate[]) field.get(entry);

					hashCode = Integer.toString(certificates[0].hashCode());

					field = entry.getClass().getDeclaredField("alias");
					field.setAccessible(true);
					alias = (String) field.get(entry);

					if (!alias.equals(hashCode)) {
						field.set(entry, alias.concat(" - ").concat(hashCode));
					}
				}
			}
		} catch (IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException ex) {
			logger.info(ex.getMessage());
			ex.printStackTrace();
		}
	}

	public CallbackHandler getCallback() {
		return callback;
	}

	public void setCallback(CallbackHandler callback) {
		this.callback = callback;
	}

	@Override
	public KeyStore getKeyStore(String pinNumber) {
		return null;
	}

}
