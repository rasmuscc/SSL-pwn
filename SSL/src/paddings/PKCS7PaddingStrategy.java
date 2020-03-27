package paddings;

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
	public byte[] getPadding(int blockSize, byte[] data) {
		// Get size of padding that needs to go on last block
		int paddingSize = blockSize - data.length % blockSize;

		byte[] padding = new byte[paddingSize];
		for (int i = 0; i < paddingSize; i++) {
			padding[i] = charPadding[paddingSize - 1];
		}

		int paddedDataLength = data.length + paddingSize;
		byte[] paddedData = new byte[paddedDataLength];

		System.arraycopy(padding, 0, paddedData, data.length, padding.length);

		System.arraycopy(data, 0, paddedData, 0, data.length);


		return paddedData;
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
		boolean res = true;
		for (int i = 14; i > 15 - length; i--) {
			res = padding[i] == charPadding[length - 1];
			if (!res) break;
		}
		return res;
	}
}
