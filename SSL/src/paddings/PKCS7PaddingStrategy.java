package paddings;

import strategyinterfaces.PaddingStrategy;

public class PKCS7PaddingStrategy implements PaddingStrategy {


	/**
	 * Create padding depending on the length of the message
	 * @param blockSize size of the blocks, used to determine how much padding is needed
	 * @param data message that needs to be padded
	 * @return padded data/message
	 */
	@Override
	public byte[] getPadding(int blockSize, byte[] data) {
		// Get size of padding that needs to go on last block
		int paddingSize = blockSize - data.length % blockSize;

		// make array of padding and fill it up with the byte of the paddingsize
		byte[] padding = new byte[paddingSize];
		for (int i = 0; i < paddingSize; i++) {
			padding[i] = (byte) (paddingSize - 1);
		}

		// make new array for padded message
		int paddedDataLength = data.length + paddingSize;
		byte[] paddedData = new byte[paddedDataLength];

		// copy both the padding and original data into new array
		System.arraycopy(padding, 0, paddedData, data.length, padding.length);
		System.arraycopy(data, 0, paddedData, 0, data.length);


		return paddedData;
	}


	/**
	 * Checks if padding is valid for decrypted data
	 * @param padding a decrypted message that needs to be checked for correct padding
	 * @return true if valid, else false
	 */
	@Override
	public boolean checkPadding(byte[] padding) {
		boolean res = false;
		// checks if last byte in padding equals valid padding byte
		for (int k = 0; k < 16; k++) {
			// if the last byte is a valid byte, count if the number of valid bytes is correct
			if (padding[15] == (byte) (k)) {
				res = counter(padding,k + 1);
				// if the number is valid break and return
				if (res) {
					break;
				}
			}
		}

		return res;
	}


	/**
	 * Counts that a given valid byte is repeated the correct amount of times
	 * @param padding a decrypted message that needs to be checked for correct padding
	 * @param length the length that corresponds to the valid byte found
	 * @return true if the number of bytes is correct, else false
	 */
	private boolean counter(byte[] padding, int length) {
		boolean res = true;

		// check if the remaining bytes up to length is correct
		for (int i = 14; i > 15 - length; i--) {
			res = padding[i] == (byte) (length - 1);
			// if false break and return
			if (!res) break;
		}
		return res;
	}
}
