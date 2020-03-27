import abstractfactories.AbstractFactory;
import abstractfactories.NormalCBCMode;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;


public class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;
    private byte[] cipherText;

    public static void main(String[] args) {
        new Server(new NormalCBCMode());
    }

    public Server(AbstractFactory abstractFactory) {
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        try {
            cipherText = modeStrategy.encrypt("Rasmus ser gay porno med Jannick");
        } catch (Exception e) {

        }

    }

    public byte[] getCipherText() {
        return cipherText;
    }


    public boolean isPaddingCorrect(byte[] enc) {
        byte[] decryption = null;
        try {
            decryption = modeStrategy.decrypt(enc);
        } catch (Exception e) {

        }

        return paddingStrategy.checkPadding(decryption);
    }

}