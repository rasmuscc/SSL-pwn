package paddings;

import strategyinterfaces.PaddingStrategy;

public class PKCS7PaddingStrategy implements PaddingStrategy {

	private byte[] charPadding;

	public PKCS7PaddingStrategy() {
		charPadding = new byte[16];

		charPadding[0] = (byte) 1;
		charPadding[1] = (byte) 2;
		charPadding[2] = (byte) 3;
		charPadding[3] = (byte) 4;
		charPadding[4] = (byte) 5;
		charPadding[5] = (byte) 6;
		charPadding[6] = (byte) 7;
		charPadding[7] = (byte) 8;
		charPadding[8] = (byte) 9;
		charPadding[9] = (byte) 10;
		charPadding[10] = (byte) 11;
		charPadding[11] = (byte) 12;
		charPadding[12] = (byte) 13;
		charPadding[13] = (byte) 14;
		charPadding[14] = (byte) 15;
		charPadding[15] = (byte) 16;
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
