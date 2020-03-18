import abstractfactories.AbstractFactory;
import abstractfactories.NormalCBCMode;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;


class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;

    public static void main(String[] args) {
        new Server(new NormalCBCMode());
    }

    private Server(AbstractFactory abstractFactory) {
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        byte[] encryption = modeStrategy.encrypt("HVADSÅDER");
        byte[] decryption = modeStrategy.decrypt(encryption);
        System.out.println(new String(decryption));
        paddingStrategy.checkPadding(decryption);
    }

    private int listen (int port) {
        return - 1;
    }
}