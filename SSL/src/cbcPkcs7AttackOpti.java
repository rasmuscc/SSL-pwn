import abstractfactories.NormalCBCMode;

import java.util.Arrays;
import java.util.Scanner;

class cbcPkcs7AttackOpti {

	private Server server;
	private byte[] cipherText;
	private byte[] tempEnc;
	private byte[] encSubArr;
	private int blockSize = 16;
	private int[] intermediate;
	private int[] padI = new int[blockSize];
	private byte[] padDelta = new byte[blockSize];
	private Scanner scanner;
	private int iter;
	private int block;
	private String freqAlpha = "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}";

	public static void main(String[] args) {
		new cbcPkcs7AttackOpti();
	}

	public cbcPkcs7AttackOpti() {
		server = new Server(new NormalCBCMode());
		scanner = new Scanner(System.in);

		cipherText = server.getCipherText();

		// make sub arrays for calculations
		encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
		tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
		// array for storing the bytes of the intermediate representation
		intermediate = new int[encSubArr.length];

		int numberOfBlocks = cipherText.length / blockSize;
		block = 1;

		int startPos;
		iter = 1;

		int padding = 0;

		// begin plaintext recovery
		String plaintext = "";
		System.out.println("Encrypted message: " + new String(cipherText));
		System.out.println("First remove padding");
		System.out.println("Press enter to continue or say no to exit");
		while (scanner.hasNextLine()) {
			if (scanner.nextLine().equals("no")) {
				break;
			}
			startPos = tempEnc.length - iter;

			if (iter == 1 && block == 1) {
				// first find out size of padding
				findPadding(startPos);
				System.out.println("Padding of size " + iter + " is now removed");
				padding = iter;
				for (int i = iter; i < blockSize + 1; i++) {
					startPos = tempEnc.length - i;
					plaintext = getNextByte(startPos, i) + plaintext;
				}
				System.out.println("Recovered plaintext is now: " + plaintext);
				System.out.println("Press enter to continue or say no to exit");
			} else {
				// update plaintext with next byte
				for (int i = iter; i < blockSize + 1; i++) {
					startPos = tempEnc.length - i;
					plaintext = getNextByte(startPos, i) + plaintext;
				}

				System.out.println("Recovered plaintext is now: " + plaintext);
				System.out.println("Press enter to continue or say no to exit");
			}

			if (block + 1 != numberOfBlocks) {
				// if end of block is reached make new temporary arrays and increase block number
				block++;
				tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - blockSize - (block * blockSize), cipherText.length - ((block - 1) * blockSize));
				encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - blockSize - (block * blockSize), cipherText.length - ((block - 1) * blockSize));
				intermediate = new int[tempEnc.length];
				// start over for next block
				iter = 1;
			} else if (block + 1 == numberOfBlocks) {
				// terminate if all blocks have been decrypted
				System.out.println("Full plaintext recovered: " + plaintext);

				System.out.println("Number of queries made: " + server.getQueries());
				System.out.println("Average queries per byte including padding: " + 1.0 * server.getQueries()/(plaintext.length() + padding));
				break;
			}
		}
	}

	/**
	 * find padding and make arrays ready for finding next byte
	 * @param pos posttion in arrays
	 */
	private void findPadding(int pos) {

		// get size of padding
		int paddingSize = getPaddingSize(pos);

		// make intermediate array for padding
		for (int j = 0; j < paddingSize; j++) {
			padI[(blockSize - 1) - j] = ((int) padDelta[(blockSize - 1) - j] ^ paddingSize);
		}

		// insert padding intermediates into intermediate array
		System.arraycopy(padI, padI.length - paddingSize, intermediate, intermediate.length - paddingSize, paddingSize);

		// calculate new byte representation for next iteration
		for (int j = 0; j < paddingSize; j++) {
			tempEnc[(blockSize - 1) - j] = (byte) (padI[(blockSize - 1) - j] ^ paddingSize + 1);
		}

		// setting iter to padding size to skip padding
		iter = paddingSize;
	}


	/**
	 * getting next byte from ciphertext by finding which byte make a valid padding and prepares for next byte
	 * @param pos position in arrays
	 * @param iteration posistion in block
	 * @return res the next plaintext byte in original message
	 */
	private String getNextByte(int pos, int iteration) {

		String res = "";
		boolean notFound = true;

		// guess byte to get a valid padding
		byte[] temp = tempEnc.clone();
		for (int i = 0; i < freqAlpha.length(); i++) {
			int delta = (byte) freqAlpha.charAt(i) ^ (byte) iteration ^ encSubArr[pos - blockSize];

			temp[pos - blockSize] = (byte) delta;
			if (server.isPaddingCorrect(temp)) {

				// calculate intermediate for pos
				intermediate[pos] = (byte) (delta ^ iteration);

				// calculate new byte representation for next iteration
				for (int j = 0; j < iteration; j++) {
					tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ iteration + 1);
				}

				// get original plaintext byte
				res = decrypt((byte) pos, intermediate[pos]);
				notFound = false;
				break;
			}
		}

		int remainingBytes = 256 - freqAlpha.length();

		int startingPos = freqAlpha.charAt(freqAlpha.length()-1);

		if (notFound) {
			for (int i = startingPos; i < startingPos + remainingBytes + 1; i++) {
				int delta = (byte) i ^ (byte) iteration ^ encSubArr[pos - 16];
				temp[pos - blockSize] = (byte) delta;
				if (server.isPaddingCorrect(temp)) {

					// calculate intermediate for pos
					intermediate[pos] = (byte) (delta ^ iteration);

					// calculate new byte representation for next iteration
					for (int j = 0; j < iteration; j++) {
						tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ iteration + 1);
					}

					// get original plaintext byte
					res = decrypt((byte) pos, intermediate[pos]);
					break;
				}
			}
		}


		return res;
	}


	/**
	 * Checks padding and returns the size
	 * @param pos position in arrays
	 * @return paddingSize
	 */
	private int getPaddingSize(int pos) {
		int paddingSize = 0;

		// changing bytes to something illegal to see when padding is not valid
		for (int j = (blockSize - 1); j > -1; j--) {
			byte[] temp = tempEnc.clone();
			temp[pos - blockSize - j] = (byte) 17;

			// if not valid, padding is broken and size is found
			if (!server.isPaddingCorrect(temp)) {
				paddingSize = j + 1;
				break;
			}
		}

		// getting deltas for padding
		for (int j = 0; j < paddingSize; j++) {
			padDelta[(blockSize - 1) - j] = encSubArr[(blockSize - 1) - j];
		}

		return paddingSize;
	}


	private String decrypt(int pos, int inter) {
		return new String(new byte[] { (byte) ((int) encSubArr[pos - blockSize] ^ inter) });
	}

}