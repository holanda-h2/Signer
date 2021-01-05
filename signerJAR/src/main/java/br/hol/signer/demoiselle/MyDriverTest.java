package br.hol.signer.demoiselle;

import java.io.File;
import java.util.SortedMap;
import java.util.TreeMap;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;

public class MyDriverTest {

	public static final String KEY_OS_NAME = "os.name";

	public static String getSOName() {
		return System.getProperty(MyDriverTest.KEY_OS_NAME);
	}

	public static String detectDriver() {
		String driverPath = "";

		String winRoot = (System.getenv("SystemRoot") == null) ? ""
				: System.getenv("SystemRoot").replaceAll("\\\\", "/");
		SortedMap<String, String> map = new TreeMap<String, String>();

		if (MyDriverTest.getSOName().startsWith("W")) {
			// ------------ Windows ------------
			map.put("TokenOuSmartCard_00_Safesign", winRoot.concat("/system32/ngp11v211.dll"));
			map.put("TokenOuSmartCard_01_safenet", winRoot.concat("/system32/aetpkss1.dll"));
			map.put("TokenOuSmartCard_02_gemalto", winRoot.concat("/system32/gclib.dll"));
			map.put("TokenOuSmartCard_03_gemsafe", winRoot.concat("/system32/pk2priv.dll"));
			map.put("TokenOuSmartCard_04_gemsafe", winRoot.concat("/system32/w32pk2ig.dll"));
			map.put("TokenOuSmartCard_05_safenet", winRoot.concat("/system32/eTPkcs11.dll"));
			map.put("TokenOuSmartCard_06_pronova", winRoot.concat("/system32/acospkcs11.dll"));
			map.put("TokenOuSmartCard_07_datakey", winRoot.concat("/system32/dkck201.dll"));
			map.put("TokenOuSmartCard_08_rainbow", winRoot.concat("/system32/dkck232.dll"));
			map.put("TokenOuSmartCard_09_rainbow", winRoot.concat("/system32/cryptoki22.dll"));
			map.put("TokenOuSmartCard_10_dodcacactivcard", winRoot.concat("/system32/acpkcs.dll"));
			map.put("TokenOuSmartCard_11_cryptoflex", winRoot.concat("/system32/slbck.dll"));
			map.put("TokenOuSmartCard_12_safeweb", winRoot.concat("/system32/cmP11.dll"));
			map.put("TokenOuSmartCard_13_watchdata", winRoot.concat("/system32/WDPKCS.dll"));
			map.put("TokenOuSmartCard_14_watchdata",
					winRoot.concat("/System32/Watchdata/Watchdata Brazil CSP v1.0/WDPKCS.dll"));
			map.put("TokenOuSmartCard_15_gemplus", "/Arquivos de programas/Gemplus/GemSafe Libraries/BIN/gclib.dll");
			map.put("TokenOuSmartCard_16_gemplus", "/Program Files/Gemplus/GemSafe Libraries/BIN/gclib.dll");
			map.put("TokenOuSmartCard_17_watchdata", winRoot.concat("/System32/WDICP_P11_CCID_v34.dll"));
			map.put("TokenOuSmartCard_18_watchdata", winRoot.concat("/SysWOW64/WDICP_P11_CCID_v34.dll"));
			map.put("TokenOuSmartCard_19_Oberthur_x86",
					"/Program Files (x86)/Oberthur Technologies/AWP/DLLs/OcsCryptolib_P11.dll");
			map.put("TokenOuSmartCard_20_pronova_Athena", winRoot.concat("/system32/asepkcs.dll"));

			map.put("TokenOuSmartCard_48_neoid", winRoot.concat("/system32/SerproPkcs11.dll"));

		} else if (MyDriverTest.getSOName().startsWith("L")) {
			// ------------ Linux ------------
			map.put("TokenOuSmartCard_21_safesign", "/usr/lib/libaetpkss.so");
			map.put("TokenOuSmartCard_22_alladin", "/usr/lib/libgpkcs11.so");
			map.put("TokenOuSmartCard_23_lutzbehnke", "/usr/lib/libgpkcs11.so.2");

			// Token Verde do Serpro
			map.put("TokenOuSmartCard_24_pronova", "/usr/lib/libepsng_p11.so");
			map.put("TokenOuSmartCard_25_pronova", "/usr/lib/libepsng_p11.so.1");
			map.put("TokenOuSmartCard_26_pronova", "/usr/local/ngsrv/libepsng_p11.so.1");

			// Token Azul do Serpro
			map.put("TokenOuSmartCard_27_safenet", "/usr/lib/libeTPkcs11.so");
			map.put("TokenOuSmartCard_28_safenet", "/usr/lib/libeToken.so");
			map.put("TokenOuSmartCard_29_safenet", "/usr/lib/libeToken.so.4");
			map.put("TokenOuSmartCard_30_safenet", "/usr/lib/libcmP11.so");
			map.put("TokenOuSmartCard_31_safenet", "/usr/lib/libwdpkcs.so");
			map.put("TokenOuSmartCard_32_safenet", "/usr/local/lib64/libwdpkcs.so");
			map.put("TokenOuSmartCard_33_safenet", "/usr/local/lib/libwdpkcs.so");

			// Token Branco do Serpro
			map.put("TokenOuSmartCard_34_watchdata", "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so");
			map.put("TokenOuSmartCard_35_watchdata", "/usr/lib/watchdata/lib/libwdpkcs.so");
			map.put("TokenOuSmartCard_36_watchdata", "/opt/watchdata/lib64/libwdpkcs.so");

			// Token GD do Serpro
			map.put("TokenOuSmartCard_37_GDBurti", "/usr/lib/libaetpkss.so.3");
			map.put("TokenOuSmartCard_38_GDBurti", "/usr/lib/libaetpkss.so.3.0");

			map.put("TokenOuSmartCard_39_opensc", "/usr/lib/opensc-pkcs11.so");
			map.put("TokenOuSmartCard_40_opensc", "/usr/lib/pkcs11/opensc-pkcs11.so");

			map.put("TokenOuSmartCard_41_pronova", "/usr/local/ngsrv/libepsng_p11.so.1.2.2");
			map.put("TokenOuSmartCard_42_Oberthur", "/usr/local/AWP/lib/libOcsCryptoki.so");

			// Token Azul do Serpro
			map.put("TokenOuSmartCard_51_safenet_64", "/usr/lib64/libeToken.so");
			map.put("TokenOuSmartCard_52_ePass2003", "/opt/ePass2003-Castle-20141128/i386/redist/libcastle.so.1.0.0");
			map.put("TokenOuSmartCard_53_opensc64", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so");
			map.put("TokenOuSmartCard_54_opensc64", "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so");

			// Certificado em Nuvem SERPRO NEOID - Linux
			map.put("TokenOuSmartCard_49_neoid", "/usr/lib/libneoidp11.so");

		} else if (MyDriverTest.getSOName().startsWith("D")) {

			// ------------ Mac ------------
			// Token Branco do Serpro
			map.put("TokenOuSmartCard_43_watchdata", "//usr//lib//libwdpkcs.dylib");
			map.put("TokenOuSmartCard_44_watchdata", "//usr//local/lib//libwdpkcs.dylib");
			map.put("TokenOuSmartCard_45_watchdataBB",
					"//Applications//WatchKey USB Token Admin Tool.app//Contents//MacOS//lib//libWDP11_BR_GOV.dylib");
			map.put("TokenOuSmartCard_46_safenet", "//usr//local//lib//libetpkcs11.dylib");
			map.put("TokenOuSmartCard_47_safenet", "//usr//local//lib//libaetpkss.dylib");

			// Certificado em Nuvem SERPRO NEOID - MacOS
			map.put("TokenOuSmartCard_50_neoid",
					"//Applications//NeoID Desktop.app//Contents//Java//tools//macos//libneoidp11.dylib");

			map.put("TokenOuSmartCard_55_gdBurty_Mac",
					"//Applications//tokenadmin.app//Contents//Frameworks//libaetpkss.dylib");

			map.put("TokenOuSmartCard_56_opensc", "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so");
			map.put("TokenOuSmartCard_57_opensc", "/usr/lib/opensc/openscÂ­pkcs11.so");
		}

		boolean successLoad = false;
		loop: for (String driver : map.keySet()) {
			try {
				MyDriverTest.testDriver(map.get(driver));
				driverPath = map.get(driver);
				successLoad = true;
				break loop;
			} catch (Throwable error) {
				// ---
			}
		}
		return driverPath;
	}

	public static boolean testDriver(String fileName) {

		boolean test = false;
		File file = new File(fileName);
		if (!file.exists() || !file.isFile()) {
			throw new KeyStoreLoaderException("File not exist.");
		}
		test = true;
		return test;

	}

}
