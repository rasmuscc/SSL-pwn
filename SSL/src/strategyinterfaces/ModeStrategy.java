package strategyinterfaces;

public interface ModeStrategy {

	byte[] encrypt(String data);

	byte[] decrypt(byte[] cipher);

}
