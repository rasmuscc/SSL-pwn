package modeOfOperations;

import strategyinterfaces.ModeStrategy;

import java.util.Random;

public class CTRModeStrategy implements ModeStrategy {

	private final int blockSize = 16;
	private byte[] key = null;
	private byte[] IV;

	public CTRModeStrategy() {
		setKey("1234567812345678");
	}

	private byte[] getIV(int seed) {
		// Should be random, but for testing we make it static
		byte[] iv = new byte[blockSize/2];
		Random random = new Random();

		for (int i = 0; i < blockSize/2; i++) {
			iv[i] = (byte) (random.nextInt(256));
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
