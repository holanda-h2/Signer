package br.hol.signer.demoiselle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Pattern;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(MyConfiguration.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	protected static final String KEY_JAVA_VERSION = "java.runtime.version";
	protected static final String KEY_OS_NAME = "os.name";
	protected static final String KEY_OS_VERSION = "os.version";
	protected static final String VAR_PKCS11_CONFIG = "PKCS11_CONFIG_FILE";
	protected static final String VAR_PKCS11_DRIVER = "PKCS11_DRIVER";
	protected static final String CUSTOM_CONFIG_PATH = "user.home";
	protected static final String CUSTOM_CONFIG_FILENAME = "drivers.config";
	protected static final String FILE_SEPARATOR = "file.separator";
	protected static final String MSCAPI_DISABLED = "mscapi.disabled";
	protected static final String CONFIG_FILE_DIR = ".signer";
	protected static final String CONFIG_FILE_PATH = "drivers.properties";
	protected static boolean MSCAPI_ON = true;

	private static final MyConfiguration instance = new MyConfiguration();

	public static MyConfiguration getInstance() {
		return MyConfiguration.instance;
	}

	private final SortedMap<String, String> drivers = new TreeMap<String, String>();

	private MyConfiguration() {
		String winRoot = (System.getenv("SystemRoot") == null) ? ""
				: System.getenv("SystemRoot").replaceAll("\\\\", "/");
		SortedMap<String, String> map = new TreeMap<String, String>();

		boolean successLoad = false;
		for (String driver : map.keySet()) {
			try {
				this.addDriver(driver, map.get(driver));
				logger.info(coreMessagesBundle.getString("info.load.driver", driver));
				successLoad = true;
			} catch (Throwable error) {
				logger.debug(coreMessagesBundle.getString("error.load.driver", driver));
			}
		}

		if (!successLoad) {
			logger.error(coreMessagesBundle.getString("error.load.driver.null"));
		}

		try {
			this.getPKCS11DriverFromVariable();
		} catch (Throwable error) {
			logger.error(coreMessagesBundle.getString("error.load.driver.null"));
		}

	}

	public String getJavaVersion() {
		return System.getProperty(MyConfiguration.KEY_JAVA_VERSION);
	}

	public boolean isMSCapiDisabled() {
		boolean enabled = Boolean.parseBoolean(this.getContentFromVariables(MyConfiguration.MSCAPI_DISABLED));
		return enabled;
	}

	public String getSO() {
		return System.getProperty(MyConfiguration.KEY_OS_NAME);
	}

	public Integer getSoVersion() {

		Pattern p = Pattern.compile("[^0-9]");
		String varVersion = System.getProperty(MyConfiguration.KEY_OS_VERSION);
		int pos = varVersion.indexOf("-");
		varVersion = varVersion.substring(0, pos);
		String numericVersion = p.matcher(varVersion).replaceAll("");
		Integer integerVersion = Integer.valueOf(numericVersion);

		return integerVersion;

	}

	public Integer getSoVersionRelease() {

		Pattern p = Pattern.compile("[^0-9]");
		String varVersion = System.getProperty(MyConfiguration.KEY_OS_VERSION);
		String numericVersion = p.matcher(varVersion).replaceAll("");
		Integer integerVersion = Integer.valueOf(numericVersion);

		return integerVersion;

	}

	public SortedMap<String, String> getDrivers() {
		return this.drivers;
	}

	public void addDriver(String name, String fileName) {

		if (name == null || "".equals(name)) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.name.null"));
		}

		if (fileName == null || "".equals(fileName)) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.driver.null"));
		}

		File file = new File(fileName);
		if (!file.exists() || !file.isFile()) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.path.invalid"));
		}

		logger.debug(coreMessagesBundle.getString("info.add.driver", name, fileName));
		this.drivers.put(name, fileName);

	}

	public void addDriver(String fileName) {
		if (fileName == null || fileName.trim().length() <= 0) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("warn.file.null"));
		}
		String driverName = fileName.replaceAll("\\\\", "/");
		int begin = driverName.lastIndexOf("/");
		begin = begin <= -1 ? 0 : begin + 1;
		int end = driverName.length();
		driverName = driverName.substring(begin, end);

		this.addDriver(driverName, fileName);

	}

	public String getPKCS11ConfigFile() {
		String filePath = this.getContentFromVariables(MyConfiguration.VAR_PKCS11_CONFIG);
		return filePath;
	}

	public void getPKCS11DriverFromVariable() {

		String driverInfo = this.getContentFromVariables(MyConfiguration.VAR_PKCS11_DRIVER);

		if (driverInfo != null) {

			if (driverInfo.lastIndexOf("::") > 0) {
				String[] driverInfoSplited = driverInfo.split("::");
				if (driverInfoSplited.length == 2) {
					this.addDriver(driverInfoSplited[0], driverInfoSplited[1]);
				}
			} else {
				this.addDriver(driverInfo);
			}

		}

	}

	private String getContentFromVariables(String key) {
		String content = System.getenv(key);
		if (content == null) {
			content = System.getenv(key.toLowerCase());
		}
		if (content == null) {
			content = System.getenv(key.toUpperCase());
		}

		if (content == null) {
			content = System.getProperty(key);
		}
		if (content == null) {
			content = System.getProperty(key.toLowerCase());
		}
		if (content == null) {
			content = System.getProperty(key.toUpperCase());
		}

		if (content == null) {
			String filename = System.getProperty(CUSTOM_CONFIG_PATH) + System.getProperty(FILE_SEPARATOR)
					+ CUSTOM_CONFIG_FILENAME;
			boolean exists = (new File(filename)).exists();
			if (exists) {
				content = filename;
			}
		}

		return content;
	}

	private void loadFromHomeFile(Map<String, String> map) {
		Properties prop = new Properties();
		InputStream input = null;

		try {
			input = new FileInputStream(MyConfiguration.getConfigFilePath());
			prop.load(input);
			Set<String> keys = prop.stringPropertyNames();
			Iterator<String> it = keys.iterator();
			while (it.hasNext()) {
				String key = it.next();
				map.put(key, prop.getProperty(key));
			}
		} catch (FileNotFoundException e) {
			new File(System.getProperty(CUSTOM_CONFIG_PATH) + System.getProperty(FILE_SEPARATOR) + CONFIG_FILE_DIR)
					.mkdir();
			try {
				new File(MyConfiguration.getConfigFilePath()).createNewFile();
			} catch (IOException e1) {
				e1.printStackTrace();
			}

		} catch (IOException e) {
		}

	}

	public static String getConfigFilePath() {
		String separator = System.getProperty(FILE_SEPARATOR);
		return System.getProperty(CUSTOM_CONFIG_PATH) + separator + CONFIG_FILE_DIR + separator + CONFIG_FILE_PATH;
	}

	public static boolean isMSCAPI_ON() {
		return MSCAPI_ON;
	}

	public static void setMSCAPI_ON(boolean mSCAPI_ON) {
		MSCAPI_ON = mSCAPI_ON;
	}

}
