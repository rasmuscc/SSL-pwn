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

	public static void main(String[] args) throws Exception {
		new cbcPkcs7AttackOpti(false);
	}

	public cbcPkcs7AttackOpti(boolean isTesting) throws Exception {
		server = new Server(new NormalCBCMode());
		scanner = new Scanner(System.in);

		cipherText = server.getCipherText();

		// make sub arrays for calculations
		// 32 bytes of original encryption encSubArr stays the same and tempEnc is manipulated one byte at a time
		encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
		tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
		// array for storing the bytes of the intermediate representation
		intermediate = new int[encSubArr.length];

		int numberOfBlocks = cipherText.length / blockSize;
		block = 1;

		int startPos;
		iter = 1;

		int padding = 0;
		String plaintext = "";

		if (!isTesting) {
			// begin plaintext recovery
			System.out.println("Encrypted message: " + new String(cipherText));
			System.out.println("First remove padding");
			System.out.println("Press enter to continue or say no to exit");
			// decrypts 1 block at a time
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
					// get remaining plaintext of first block
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
					System.out.println("Average queries per byte including padding: " + 1.0 * server.getQueries() / (plaintext.length() + padding));
					break;
				}
			}
		} else {
			boolean cond = true;

			while (cond) {
				startPos = tempEnc.length - iter;

				if (iter == 1 && block == 1) {
					// first find out size of padding
					findPadding(startPos);
					padding = iter;
					// get remaining plaintext of first block
					for (int i = iter; i < blockSize + 1; i++) {
						startPos = tempEnc.length - i;
						plaintext = getNextByte(startPos, i) + plaintext;
					}
				} else {
					// update plaintext with next byte
					for (int i = iter; i < blockSize + 1; i++) {
						startPos = tempEnc.length - i;
						plaintext = getNextByte(startPos, i) + plaintext;
					}
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
					System.out.println("Number of queries made: " + server.getQueries());
					System.out.println("Average queries per byte including padding: " + 1.0 * server.getQueries()/(plaintext.length() + padding));
					break;
				}

			}
		}
	}

	/**
	 * find padding and make arrays ready for finding next byte
	 * @param pos posttion in arrays
	 */
	private void findPadding(int pos) throws Exception {

		// get size of padding
		int paddingSize = getPaddingSize(pos);

		// make intermediate array for padding
		for (int j = 0; j < paddingSize; j++) {
			padI[(blockSize - 1) - j] = ((int) padDelta[(blockSize - 1) - j] ^ (paddingSize - 1));
		}

		// insert padding intermediates into intermediate array
		System.arraycopy(padI, padI.length - paddingSize, intermediate, intermediate.length - paddingSize, paddingSize);

		// calculate new byte representation for next iteration
		for (int j = 0; j < paddingSize; j++) {
			tempEnc[(blockSize - 1) - j] = (byte) (padI[(blockSize - 1) - j] ^ paddingSize);
		}

		// setting iter to padding size to skip padding
		iter = paddingSize;
	}


	/**
	 * Gets next byte from ciphertext by finding which byte from the last block makes a valid padding and setup the last block for next byte
	 * Is optimized using a freqAlpha array containing frequent characters in order of most used, and computes a delta using that character
	 * @param pos position in arrays
	 * @param iteration posistion in block
	 * @return res the next plaintext byte in original message
	 */
	private String getNextByte(int pos, int iteration) throws Exception {

		String res = "";
		// bool to know if plaintext we are trying to recover is not part of the freqAlpha array
		boolean notFound = true;

		// guess byte to get a valid padding
		byte[] temp = tempEnc.clone();
		// starts with freqAlpha array in order
		for (int i = 0; i < freqAlpha.length(); i++) {
			// our guess delta if our freqAlpha character is correct
			int delta = (byte) freqAlpha.charAt(i) ^ (byte) (iteration - 1) ^ encSubArr[pos - blockSize];

			temp[pos - blockSize] = (byte) delta;
			if (server.isPaddingCorrect(temp)) {

				// calculate intermediate for pos
				intermediate[pos] = (byte) (delta ^ (iteration - 1));

				// calculate new byte representation for next iteration
				for (int j = 0; j < iteration; j++) {
					tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ iteration);
				}

				// get original plaintext byte, we know it is the from freqAlpha we just guessed
				res = freqAlpha.charAt(i) + "";
				// plaintext is found so no need to continue with other bytes
				notFound = false;
				break;
			}
		}

		// find out how many bytes remains depending on our freqAlpha array
		int remainingBytes = 256 - freqAlpha.length();
		// starts where the freqAlpha array ends
		int startingPos = freqAlpha.charAt(freqAlpha.length()-1);

		if (notFound) {
			for (int i = startingPos; i < startingPos + remainingBytes + 1; i++) {
				// our guess is delta
				int delta = (byte) i ^ (byte) iteration ^ encSubArr[pos - 16];
				temp[pos - blockSize] = (byte) delta;

				if (server.isPaddingCorrect(temp)) {

					// calculate intermediate for pos
					intermediate[pos] = (byte) (delta ^ (iteration - 1));

					// calculate new byte representation for next iteration
					for (int j = 0; j < iteration; j++) {
						tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ iteration);
					}

					// get original plaintext byte
					res = decrypt((byte) pos, intermediate[pos]);
					break;
				}
			}
		}

		// return recovered plaintext byte
		return res;
	}


	/**
	 * Checks padding and returns the size
	 * @param pos position in arrays
	 * @return paddingSize
	 */
	private int getPaddingSize(int pos) throws Exception {
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

	/**
	 * Returns the plaintext of byte on pos
	 * @param pos position in arrays
	 * @param inter intermediate byte
	 * @return String of plaintext byte
	 */
	private String decrypt(int pos, int inter) {
		return new String(new byte[] { (byte) ((int) encSubArr[pos - blockSize] ^ inter) });
	}

}