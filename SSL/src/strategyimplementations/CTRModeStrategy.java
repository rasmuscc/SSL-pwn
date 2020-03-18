package strategyimplementations;

import strategyinterfaces.ModeStrategy;

public class CTRModeStrategy implements ModeStrategy {

	private byte[] key;

	public CTRModeStrategy() {
		setKey("aaaaaaaaaaaaaaaa");
	}

	private byte[] getIV(int seed) {
		// Should be random, but for testing we make it static
		byte[] iv = new byte[8];
		for (int i = 0; i < 8; i++) {
			iv[i] = (byte) 'a';
		}
		return iv;
	}

	private void setKey(String init) {
		key = init.getBytes();
	}

	@Override
	public byte[] encrypt(String data) {
		return new byte[0];
	}

	@Override
	public byte[] decrypt(byte[] cipher) {
		return new byte[0];
	}
}
