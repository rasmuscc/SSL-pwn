package strategyimplementations;

import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

import java.util.Arrays;
import java.util.Random;

public class CBCModeStrategy implements ModeStrategy {

	private final int blockSize = 16;
	private byte[] key = null;
	private byte[] IV;
	private PaddingStrategy paddingStrategy;
	private char[] alphabet = "abcdefghijklmnopqrstuvwxyz".toCharArray();

	public CBCModeStrategy(PaddingStrategy paddingStrategy) {
		setKey("1234567812345678");
		IV = getIV();
		this.paddingStrategy = paddingStrategy;
	}


	public byte[] getIV() {
		// Should be random, but for testing we make it static
		byte[] iv = new byte[16];
		Random random = new Random();
		for (int i = 0; i < 16; i++) {
			iv[i] = (byte) (random.nextInt(256) + 1);
			//iv[i] = (byte) alphabet[random.nextInt(alphabet.length - 1)];
		}
		return iv;
	}

	private void setKey(String init) {
		key = init.getBytes();
	}

	@Override
	public byte[] encrypt(String data) {
		byte[] dataAsByteArray = data.getBytes();

		int numberOfBlocks = (dataAsByteArray.length / blockSize) + 1;

		// Get size of padding that needs to go on last block
		int paddingSize = blockSize - dataAsByteArray.length % blockSize;

		byte[] iv = IV;

		int paddedDataLength = dataAsByteArray.length + paddingSize;
		byte[] paddedData = new byte[paddedDataLength];

		// Add padding to the last block
		byte[] padding = paddingStrategy.getPadding(paddingSize);

		System.arraycopy(padding, 0, paddedData, dataAsByteArray.length, padding.length);

		System.arraycopy(dataAsByteArray, 0, paddedData, 0, dataAsByteArray.length);

		byte[] encryptedData = new byte[paddedDataLength + iv.length];

		for (int i = 0; i < numberOfBlocks; i++) {
			byte[] blockToEncrypt = Arrays.copyOfRange(paddedData, i * 16, (i + 1) * 16);
			byte[] encryptedBlock = encryptBlockCBC(blockToEncrypt, iv);
			System.arraycopy(encryptedBlock, 0, encryptedData, iv.length + (i * 16), 16);
			iv = encryptedBlock;
		}

		System.arraycopy(IV, 0, encryptedData, 0, iv.length);

		return encryptedData;

	}

	private byte[] encryptBlockCBC(byte[] block, byte[] prevBlock){
		byte[] encryptedBlock = new byte[blockSize];

		// Xor with previous block
		for (int i = 0; i < blockSize; i++) {
			encryptedBlock[i] = (byte) (block[i] ^ prevBlock[i]);
		}

		// Encrypt using caesar variant (shit but irrelevant for POC)
		for (int i = 0; i < blockSize; i++) {
			encryptedBlock[i] = (byte) (encryptedBlock[i] ^ key[i]);
		}

		return encryptedBlock;
	}

	public byte[] decrypt(byte[] cipher) {
		byte[] decryptedData = new byte[cipher.length];
		int numberOfBlocks = cipher.length / blockSize;

		byte[] iv;

		for (int i = numberOfBlocks - 1; i > 0; i--) {
			iv = Arrays.copyOfRange(cipher, (i-1) * 16, i * 16);

			byte[] blockToDecrypt = Arrays.copyOfRange(cipher, i * 16, (i+1) * 16);
			byte[] decryptedBlock = decryptBlockCBC(blockToDecrypt, iv);
			System.arraycopy(decryptedBlock, 0, decryptedData, i * 16, 16);
		}
		System.arraycopy(cipher, 0, decryptedData, 0, 16);
		return decryptedData;
	}

	private byte[] decryptBlockCBC(byte[] block, byte[] prevBlock) {
		byte[] decryptedBlock = new byte[blockSize];

		// Encrypt using caesar variant (shit but irrelevant for POC)
		for (int i = 0; i < blockSize; i++) {
			decryptedBlock[i] = (byte) (block[i] ^ key[i]);
		}

		// Xor with previous block
		for (int i = 0; i < blockSize; i++) {
			decryptedBlock[i] = (byte) (decryptedBlock[i] ^ prevBlock[i]);
		}



		return decryptedBlock;
	}
}
