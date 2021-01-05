package br.hol.crypto;

public class KeyInfo {

	private KeyType keyType;
	private String algorithm;
	private Integer size;
	private String detailedAlgorithm;

	public KeyInfo(KeyType keyType, String algorithm) {
		this(keyType, algorithm, null, algorithm);
	}

	public KeyInfo(KeyType keyType, String algorithm, Integer size) {
		this.keyType = keyType;
		this.algorithm = algorithm;
		this.size = size;
		this.detailedAlgorithm = algorithm + Integer.toString(size);
	}

	public KeyInfo(KeyType keyType, String algorithm, Integer size, String detailedAlgorithm) {
		this.keyType = keyType;
		this.algorithm = algorithm;
		this.size = size;
		this.detailedAlgorithm = detailedAlgorithm;
	}

	public KeyType getKeyType() {
		return keyType;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public String getDetailedAlgorithm() {
		return detailedAlgorithm;
	}

	public Integer getSize() {
		return size;
	}

}
