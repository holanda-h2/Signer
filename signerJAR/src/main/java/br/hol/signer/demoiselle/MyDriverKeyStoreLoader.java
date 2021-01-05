package br.hol.signer.demoiselle;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Formatter;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.demoiselle.signer.core.keystore.loader.DriverNotAvailableException;
import org.demoiselle.signer.core.keystore.loader.InvalidPinException;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.keystore.loader.PKCS11NotFoundException;
import org.demoiselle.signer.core.util.MessagesBundle;

public class MyDriverKeyStoreLoader implements KeyStoreLoader {

	private static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
	private static final String PKCS11_CONTENT_CONFIG_FILE = "name = %s\nlibrary = %s";
	private CallbackHandler callback;
	private Formatter formatter;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	@Override
	public KeyStore getKeyStore() {
		String configFile = MyConfiguration.getInstance().getPKCS11ConfigFile();

		if (configFile != null) {
			return this.getKeyStoreFromConfigFile(configFile);
		} else {
			return this.getKeyStoreFromDrivers();
		}
	}

	public KeyStore getKeyStoreFromDriver(String driverPath) {

		String driverName = driverPath.replaceAll("\\\\", "/");
		int begin = driverName.lastIndexOf("/");
		begin = begin <= -1 ? 0 : begin + 1;
		int end = driverName.length();
		driverName = driverName.substring(begin, end);

		return this.getKeyStoreFromDriver(driverName, driverPath);

	}

	public KeyStore getKeyStoreFromDriver(String driverName, String driverPath) {
		MyConfiguration.getInstance().addDriver(driverName, driverPath);
		KeyStore keyStore = null;
		formatter = new Formatter();

		String pkcs11ConfigSettings = formatter.format(PKCS11_CONTENT_CONFIG_FILE, driverName, driverPath).toString();
		byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
		ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

		try {
			Constructor<?> construtor = Class.forName("sun.security.pkcs11.SunPKCS11")
					.getConstructor(new Class[] { InputStream.class });
			Provider pkcs11Provider = (Provider) construtor.newInstance(new Object[] { confStream });
			Security.addProvider(pkcs11Provider);
			confStream.close();
			Method login = Class.forName("sun.security.pkcs11.SunPKCS11").getMethod("login",
					new Class[] { Subject.class, CallbackHandler.class });
			login.invoke(Security.getProvider(pkcs11Provider.getName()), new Object[] { null, this.callback });
			keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, pkcs11Provider.getName());
			keyStore.load(null, null);

		} catch (IOException | ClassNotFoundException | IllegalAccessException | IllegalArgumentException
				| InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException
				| KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
			if (ex.getCause().toString().equals("javax.security.auth.login.FailedLoginException")) {
				throw new InvalidPinException(coreMessagesBundle.getString("error.pin.invalid"), ex);
			}

			if (ex.getCause().toString().equals("javax.security.auth.login.LoginException")) {
				throw new InvalidPinException(coreMessagesBundle.getString("error.pin.invalid"), ex);
			} else {
				throw new PKCS11NotFoundException(coreMessagesBundle.getString("error.load.module.pcks11"), ex);
			}
		}
		return keyStore;
	}

	private KeyStore getKeyStoreFromConfigFile(String configFile) {

		KeyStore keyStore = null;

		try {
			Constructor<?> construtor = Class.forName("sun.security.pkcs11.SunPKCS11")
					.getConstructor(new Class[] { String.class });
			Provider pkcs11Provider = (Provider) construtor.newInstance(new Object[] { configFile });
			Security.addProvider(pkcs11Provider);
			Method login = Class.forName("sun.security.pkcs11.SunPKCS11").getMethod("login",
					new Class[] { Subject.class, CallbackHandler.class });
			login.invoke(Security.getProvider(pkcs11Provider.getName()), new Object[] { null, this.callback });
			keyStore = KeyStore.getInstance(PKCS11_KEYSTORE_TYPE, pkcs11Provider.getName());
			keyStore.load(null, null);

		} catch (IOException | ClassNotFoundException | IllegalAccessException | IllegalArgumentException
				| InstantiationException | NoSuchMethodException | SecurityException | InvocationTargetException
				| KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
			if (ex.getCause().toString().equals("javax.security.auth.login.FailedLoginException")) {
				throw new InvalidPinException(coreMessagesBundle.getString("error.pin.invalid"), ex);
			}

			if (ex.getCause().toString().equals("javax.security.auth.login.LoginException")) {
				throw new InvalidPinException(coreMessagesBundle.getString("error.pin.invalid"), ex);
			} else {
				throw new PKCS11NotFoundException(coreMessagesBundle.getString("error.load.module.pcks11"), ex);
			}
		}
		return keyStore;
	}

	private KeyStore getKeyStoreFromDrivers() {
		KeyStoreLoaderException error = new KeyStoreLoaderException(
				coreMessagesBundle.getString("error.no.driver.compatible"));
		Map<String, String> drivers = MyConfiguration.getInstance().getDrivers();

		if (drivers == null || drivers.isEmpty()) {
			throw new DriverNotAvailableException(coreMessagesBundle.getString("error.driver.empity"));
		}

		Set<String> keyDrivers = drivers.keySet();
		KeyStore keyStore = null;

		for (String driver : keyDrivers) {
			try {
				String urlDriver = drivers.get(driver);
				keyStore = this.getKeyStoreFromDriver(driver, urlDriver);
				break;
			} catch (PKCS11NotFoundException e) {
				error.addError(e);
			} catch (InvalidPinException e) {
				throw e;
			} catch (Throwable erro) {
				error.addError(erro);
			}
		}

		if (keyStore == null && error.hasErrors()) {
			throw error;
		}

		return keyStore;
	}

	@Override
	public void setCallbackHandler(CallbackHandler callback) {
		this.callback = callback;
	}

	@Override
	public KeyStore getKeyStore(String pinNumber) {
		// TODO Auto-generated method stub
		return null;
	}

}
