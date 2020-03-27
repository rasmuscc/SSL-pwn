package strategyinterfaces;

public interface ModeStrategy {

	byte[] encrypt(String data) throws Exception;

	byte[] decrypt(byte[] cipher) throws Exception;

}
