import abstractfactories.AbstractFactory;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;



public class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;
    private byte[] cipherText;
    private int queries;


    public Server(AbstractFactory abstractFactory) throws Exception {
        // Setup encryption and padding scheme
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        String plaintext = "This is a very secret message.";

        cipherText = modeStrategy.encrypt(plaintext);

    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public int getQueries() {
        return queries;
    }

    /**
     * Checks if padding is correct when decrypting
     * @param enc ciphertext we want to know is padded correctly
     * @return true if padding is valid, false if not
     * @throws Exception
     */
    public boolean isPaddingCorrect(byte[] enc) throws Exception {
        // increment query count
        queries++;
        // decrypt message
        byte[] decryption = modeStrategy.decrypt(enc);

        // only last block is needed for checking padding
        byte[] padding = new byte[16];
        System.arraycopy(decryption, decryption.length-16, padding, 0, 16);

        // return result
        return paddingStrategy.checkPadding(padding);
    }

}