package strategyimplementations;

import strategyinterfaces.PaddingStrategy;

public class PKCS7PaddingStrategy implements PaddingStrategy {

	private byte[] charPadding;

	public PKCS7PaddingStrategy() {
		charPadding = new byte[16];

		charPadding[0] = (byte) ('\u0001');
		charPadding[1] = (byte) ('\u0002');
		charPadding[2] = (byte) ('\u0003');
		charPadding[3] = (byte) ('\u0004');
		charPadding[4] = (byte) ('\u0005');
		charPadding[5] = (byte) ('\u0006');
		charPadding[6] = (byte) ('\u0007');
		charPadding[7] = (byte) ('\u0008');
		charPadding[8] = (byte) ('\u0009');
		charPadding[9] = (byte) ('\n');
		charPadding[10] = (byte) ('\u000B');
		charPadding[11] = (byte) ('\u000C');
		charPadding[12] = (byte) ('\r');
		charPadding[13] = (byte) ('\u000E');
		charPadding[14] = (byte) ('\u000F');
		charPadding[15] = (byte) ('\u0010');
	}

	@Override
	public byte[] getPadding(int length) {
		byte[] padding = new byte[length];
		for (int i = 0; i < length; i++) {
			padding[i] = charPadding[length - 1];
		}
		return padding;
	}

	@Override
	public boolean checkPadding(byte[] decryptedData) {
		byte[] padding = new byte[16];
		System.arraycopy(decryptedData, decryptedData.length-16, padding, 0, 16);
		boolean res = false;

		for (int k = 0; k < 16; k++) {
			if (padding[15] == charPadding[k]) {
				res = counter(padding,k + 1);
				if (res) {
					break;
				}
			}
		}

		return res;
	}

	private boolean counter(byte[] padding, int length) {
		boolean res = false;
		for (int i = 15; i > 15 - length; i--) {
			res = padding[i] == charPadding[length - 1];
			if (!res) break;
		}
		return res;
	}
}
