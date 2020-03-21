import abstractfactories.AbstractFactory;
import abstractfactories.NormalCBCMode;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;


class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;
    private byte[] encryption;

    public static void main(String[] args) {
        new Server(new NormalCBCMode());
    }

    public Server(AbstractFactory abstractFactory) {
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        encryption = modeStrategy.encrypt("Insert some message here to test");
    }

    public byte[] listen() {
        return encryption;
    }

    public boolean isPaddingCorrect(byte[] enc) {
        byte[] decryption = modeStrategy.decrypt(enc);

        return paddingStrategy.checkPadding(decryption);
    }

}