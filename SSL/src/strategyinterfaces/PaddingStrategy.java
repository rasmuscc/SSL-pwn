package strategyinterfaces;

public interface PaddingStrategy {

	byte[] getPadding(int blockSize, byte[] data);

	boolean checkPadding(byte[] decryptedData);
}
