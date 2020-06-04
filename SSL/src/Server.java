import abstractfactories.AbstractFactory;
import abstractfactories.NormalCBCMode;
import strategyinterfaces.ModeStrategy;
import strategyinterfaces.PaddingStrategy;


public class Server {
    private PaddingStrategy paddingStrategy;
    private ModeStrategy modeStrategy;
    private byte[] cipherText;
    private int queries;

    public static void main(String[] args) throws Exception {
        new Server(new NormalCBCMode());
    }

    public Server(AbstractFactory abstractFactory) throws Exception {
        // Setup encryption and padding scheme
        paddingStrategy = abstractFactory.getPaddingStrategy();
        modeStrategy = abstractFactory.getModeStrategy();

        cipherText = modeStrategy.encrypt("The handshake protocol in TLS, is a protocol made to ensure a secure encryption and authenticity between a client and a server using HTTPS communication this is called the key exchange, as the name of the protocol implies, a handshake is made to agree on how the communication should be done, they agree on which version of TLS or even SSL they are going to use, they also agrees on cipher suites, the authenticity of the server is checked by the client using the servers public key and certificate, and once all this is agreed upon/checked, the two parties generate session keys for symmetric encryption after the handshake is complete.");
        System.out.println(new String(modeStrategy.decrypt(cipherText)));

    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public int getQueries() {
        return queries;
    }

    public boolean isPaddingCorrect(byte[] enc) throws Exception {
        queries++;
        byte[] decryption = modeStrategy.decrypt(enc);

        byte[] padding = new byte[16];
        System.arraycopy(decryption, decryption.length-16, padding, 0, 16);

        return paddingStrategy.checkPadding(padding);
    }

}