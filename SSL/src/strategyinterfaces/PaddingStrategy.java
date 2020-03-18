package strategyinterfaces;

public interface PaddingStrategy {

	byte[] getPadding(int length);

	boolean checkPadding(byte[] decryptedData);
}
