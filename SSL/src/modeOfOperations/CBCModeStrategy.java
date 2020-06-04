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
	private Random random = new Random();
	private PaddingStrategy paddingStrategy;

	public CBCModeStrategy(PaddingStrategy paddingStrategy) {
		// make initialization key used to make encryption key
		byte[] bytes = new byte[16];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) random.nextInt(255);
		}
		setKey(bytes);

		// random IV
		IV = getIV();
		ivParam = new IvParameterSpec(IV);

		this.paddingStrategy = paddingStrategy;
	}

	/**
	 * Create random IV
	 * @return IV of random bytes
	 */
	private byte[] getIV() {
		byte[] iv = new byte[blockSize];

		for (int i = 0; i < blockSize; i++) {
			iv[i] = (byte) (random.nextInt(255));
		}

		return iv;
	}

	/**
	 * Make encryption key used to initialize CBC encryption
	 * @param initKey parameter used in SecretkeySpec, just a random byte array with size 16
	 */
	private void setKey(byte[] initKey) {
		key = new SecretKeySpec(initKey, "AES");
	}


	/**
	 * Encrypt the message and added padding block for block
	 * @param data the message that is going to be encrypted
	 * @return encryptedData consisting of the IV and the message and padding encrypted
	 * @throws Exception
	 */
	@Override
	public byte[] encrypt(String data) throws Exception {
		// convert data/message to a byte array
		byte[] dataAsByteArray = data.getBytes();

		// find number of blocks
		int numberOfBlocks = (dataAsByteArray.length / blockSize) + 1;

		// iv is initialized to the global iv, later changes to the last encrypted block
		byte[] iv = IV;

		// Add padding to the data
		byte[] paddedData = paddingStrategy.getPadding(blockSize, dataAsByteArray);

		// make new array that can store both the iv and the padded message once encrypted
		byte[] encryptedData = new byte[paddedData.length + iv.length];

		// make sub array for block to encrypt, then encrypt that block using CBC
		for (int i = 0; i < numberOfBlocks; i++) {
			byte[] blockToEncrypt = Arrays.copyOfRange(paddedData, i * 16, (i + 1) * 16);
			byte[] encryptedBlock = encryptBlockCBC(blockToEncrypt, iv);
			System.arraycopy(encryptedBlock, 0, encryptedData, iv.length + (i * 16), 16);
			// set iv to this block for next iteration
			iv = encryptedBlock;
		}

		// set iv in before the rest of the data and return the encrypted message
		System.arraycopy(IV, 0, encryptedData, 0, iv.length);
		return encryptedData;

	}

	/**
	 * Encrypt the block using the prevblock/iv and AES
	 * @param block current block to encrypt
	 * @param prevBlock previous encrypted block or iv
	 * @return encrypted block of current block
	 * @throws Exception
	 */
	private byte[] encryptBlockCBC(byte[] block, byte[] prevBlock) throws Exception{
		byte[] encryptedBlock = new byte[blockSize];

		// initialize AES encryption
		cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);

		// first xor with previous block
		for (int i = 0; i < blockSize; i++) {
			encryptedBlock[i] = (byte) (block[i] ^ prevBlock[i]);
		}

		// Encrypt using AES and return
		encryptedBlock = cipher.doFinal(encryptedBlock);
		return encryptedBlock;
	}

	/**
	 * Decrypt the ciphertext block for block
	 * @param cipher the encrypted message with padding
	 * @return decrypted ciphertext (the original plaintext and padding)
	 * @throws Exception
	 */
	public byte[] decrypt(byte[] cipher) throws Exception {
		// array to hold decrypted data
		byte[] decryptedData = new byte[cipher.length];

		// find number of blocks
		int numberOfBlocks = cipher.length / blockSize;

		byte[] iv;

		// first find iv which is the previous block of which we want to decrypt and then decrypt block for block
		for (int i = numberOfBlocks - 1; i > 0; i--) {
			// iv set to previous block
			iv = Arrays.copyOfRange(cipher, (i-1) * 16, i * 16);

			byte[] blockToDecrypt = Arrays.copyOfRange(cipher, i * 16, (i+1) * 16);
			byte[] decryptedBlock = decryptBlockCBC(blockToDecrypt, iv);
			// copy decrypted block into the main array
			System.arraycopy(decryptedBlock, 0, decryptedData, i * 16, 16);
		}
		// iv is set into the main array (not necessary) and the decrypted data is returned
		System.arraycopy(cipher, 0, decryptedData, 0, 16);
		return decryptedData;
	}


	/**
	 * Decrypt the block using the prevBlock/IV and AES
	 * @param block current block to be decrypted
	 * @param prevBlock previous block or IV
	 * @return decrypted block
	 * @throws Exception
	 */
	private byte[] decryptBlockCBC(byte[] block, byte[] prevBlock) throws Exception {
		byte[] decryptedBlock;

		// first decrypt using AES
		cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
		decryptedBlock = cipher.doFinal(block);

		// Xor with previous block
		for (int i = 0; i < blockSize; i++) {
			decryptedBlock[i] = (byte) ( decryptedBlock[i] ^ prevBlock[i]);
		}

		return decryptedBlock;
	}
}
