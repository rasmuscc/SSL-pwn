import abstractfactories.AbstractFactory;
import abstractfactories.NormalCBCMode;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;


public class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;
    private byte[] cipherText;
    private int queries;

    public static void main(String[] args) {
        new Server(new NormalCBCMode());
    }

    public Server(AbstractFactory abstractFactory) {
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        try {
            cipherText = modeStrategy.encrypt("Rasmus ser gay porno med Jannick!");
            System.out.println(new String(modeStrategy.decrypt(cipherText)));
        } catch (Exception e) {

        }

    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public int getQueries() {
        return queries;
    }

    public boolean isPaddingCorrect(byte[] enc) {
        queries++;
        byte[] decryption = null;
        try {
            decryption = modeStrategy.decrypt(enc);
        } catch (Exception e) {

        }

        return paddingStrategy.checkPadding(decryption);
    }

}