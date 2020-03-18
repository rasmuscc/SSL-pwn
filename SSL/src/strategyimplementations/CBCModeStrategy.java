package strategyimplementations;

import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

import java.util.Arrays;

public class CBCModeStrategy implements ModeStrategy {

	private final int blockSize = 16;
	private byte[] key = null;
	private PaddingStrategy paddingStrategy;

	public CBCModeStrategy(PaddingStrategy paddingStrategy) {
		setKey("aaaaaaaaaaaaaaaa");
		this.paddingStrategy = paddingStrategy;
	}


	private byte[] getIV(int seed) {
		// Should be random, but for testing we make it static
		byte[] iv = new byte[16];
		for (int i = 0; i < 16; i++) {
			iv[i] = (byte) 'a';
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
		int paddingSize = (blockSize - dataAsByteArray.length) % blockSize;

		int paddedDataLength = dataAsByteArray.length + paddingSize;
		byte[] paddedData = new byte[paddedDataLength];

		// Add padding to the last block
		byte[] padding = paddingStrategy.getPadding(paddingSize);

		System.arraycopy(padding, 0, paddedData, dataAsByteArray.length, padding.length);

		System.arraycopy(dataAsByteArray, 0, paddedData, 0, dataAsByteArray.length);

		byte[] iv = getIV(0);

		byte[] encryptedData = new byte[paddedDataLength];

		for (int i = 0; i < numberOfBlocks; i++) {
			byte[] blockToEncrypt = Arrays.copyOfRange(paddedData, i * 16, (i + 1) * 16);
			byte[] encryptedBlock = encryptBlockCBC(blockToEncrypt, iv);
			System.arraycopy(encryptedBlock, 0, encryptedData, i * 16, 16);
			iv = encryptedBlock;
		}

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
			encryptedBlock[i] = (byte) (block[i] ^ key[i]);
		}

		return encryptedBlock;
	}

	public byte[] decrypt(byte[] cipher) {
		byte[] decryptedData = new byte[cipher.length];
		int numberOfBlocks = cipher.length / blockSize;

		byte[] iv;

		for (int i = numberOfBlocks; i > 0; i--) {
			if (i-1 == 0) {
				iv = getIV(0);
			} else {
				iv = Arrays.copyOfRange(cipher, (i-1) * 16, 16 * i);
			}
			byte[] blockToDecrypt = Arrays.copyOfRange(cipher, (i-1)*16, i*16);
			byte[] decryptedBlock = decryptBlockCBC(blockToDecrypt, iv);
			System.arraycopy(decryptedBlock, 0, decryptedData, (i-1)*16, 16);
		}

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
			decryptedBlock[i] = (byte) (block[i] ^ prevBlock[i]);
		}

		return decryptedBlock;
	}
}
