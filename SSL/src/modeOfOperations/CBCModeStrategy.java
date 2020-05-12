package modeOfOperations;

import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Random;

public class CBCModeStrategy implements ModeStrategy {

	private final int blockSize = 16;
	private SecretKeySpec key;
	private byte[] IV;
	IvParameterSpec ivParam;
	private Cipher cipher;
	private PaddingStrategy paddingStrategy;

	public CBCModeStrategy(PaddingStrategy paddingStrategy) {
		setKey("1234567812345678");
		IV = getIV();
		ivParam = new IvParameterSpec(IV);
		this.paddingStrategy = paddingStrategy;
	}


	private byte[] getIV() {
		// Should be random, but for testing we make it static
		byte[] iv = new byte[blockSize];
		Random random = new Random();

		for (int i = 0; i < blockSize; i++) {
			iv[i] = (byte) (random.nextInt(255));
		}

		return iv;
	}

	private void setKey(String initKey) {
		key = new SecretKeySpec(initKey.getBytes(), "AES");
	}

	@Override
	public byte[] encrypt(String data) throws Exception {
		byte[] dataAsByteArray = data.getBytes();


		int numberOfBlocks = (dataAsByteArray.length / blockSize) + 1;

		byte[] iv = IV;

		// Add padding to the last block
		byte[] paddedData = paddingStrategy.getPadding(blockSize, dataAsByteArray);

		byte[] encryptedData = new byte[paddedData.length + iv.length];
		for (int i = 0; i < numberOfBlocks; i++) {
			byte[] blockToEncrypt = Arrays.copyOfRange(paddedData, i * 16, (i + 1) * 16);
			byte[] encryptedBlock = encryptBlockCBC(blockToEncrypt, iv);
			System.arraycopy(encryptedBlock, 0, encryptedData, iv.length + (i * 16), 16);
			iv = encryptedBlock;
		}

		System.arraycopy(IV, 0, encryptedData, 0, iv.length);

		return encryptedData;

	}

	private byte[] encryptBlockCBC(byte[] block, byte[] prevBlock) throws Exception{
		byte[] encryptedBlock = new byte[blockSize];

		cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);

		// Xor with previous block
		for (int i = 0; i < blockSize; i++) {
			encryptedBlock[i] = (byte) (block[i] ^ prevBlock[i]);
		}

		// Encrypt using AES
		encryptedBlock = cipher.doFinal(encryptedBlock);

		return encryptedBlock;
	}

	public byte[] decrypt(byte[] cipher) throws Exception {
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

	private byte[] decryptBlockCBC(byte[] block, byte[] prevBlock) throws Exception {
		byte[] decryptedBlock;

		// Decrypt using AES
		cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
		decryptedBlock = cipher.doFinal(block);

		// Xor with previous block
		for (int i = 0; i < blockSize; i++) {
			decryptedBlock[i] = (byte) ( decryptedBlock[i] ^ prevBlock[i]);
		}



		return decryptedBlock;
	}
}
