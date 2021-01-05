package br.hol.signer.demoiselle;

import java.io.File;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.keystore.loader.implementation.FileSystemKeyStoreLoader;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyKeyStoreLoaderFactory {

	private static final Logger logger = LoggerFactory.getLogger(MyKeyStoreLoaderFactory.class);

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	public static KeyStoreLoader factoryKeyStoreLoader() {

		logger.debug(coreMessagesBundle.getString("info.keystore.no.parameter"));
		if (MyConfiguration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
			logger.debug(coreMessagesBundle.getString("info.keystore.ms"));
			if (MyConfiguration.getInstance().isMSCapiDisabled() || !MyConfiguration.isMSCAPI_ON()) {
				logger.debug(coreMessagesBundle.getString("info.keystore.ms.pkcs11"));
				return new MyDriverKeyStoreLoader();
			} else {
				logger.debug(coreMessagesBundle.getString("info.keystore.mscapi"));
				return new MyMSKeyStoreLoader();
			}
		} else {
			logger.debug(coreMessagesBundle.getString("info.keystore.pkcs11"));
			return new MyDriverKeyStoreLoader();
		}
	}

	public static KeyStoreLoader factoryKeyStoreLoader(File file) {
		return new FileSystemKeyStoreLoader(file);
	}

	public static KeyStoreLoader factoryKeyStoreLoader(Class<? extends KeyStoreLoader> clazz) {

		if (clazz == null) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.parm.clazz.null"));
		}
		KeyStoreLoader result = null;

		try {
			result = clazz.newInstance();

		} catch (IllegalAccessException | InstantiationException error) {
			throw new KeyStoreLoaderException(
					coreMessagesBundle.getString("error.class.instance", clazz.getCanonicalName()));
		}
		return result;
	}
}
