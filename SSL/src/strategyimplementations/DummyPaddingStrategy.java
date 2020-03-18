package strategyimplementations;

import strategyinterfaces.PaddingStrategy;

public class DummyPaddingStrategy implements PaddingStrategy {

	@Override
	public byte[] getPadding(int length) {
		byte[] padding = new byte[length];
		for (int i = 0; i < length; i++) {
			padding[i] = (byte) 'a';
		}
		return padding;
	}

	@Override
	public boolean checkPadding(byte[] decryptedData) {
		String data = new String(decryptedData);


		return false;
	}
}
