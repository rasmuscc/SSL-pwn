class Server {
    private final int blockSize = 16;
    private byte[] key = null;

    public static void main(String[] args) {
        System.out.println("Hello");
    }

    private int listen (int port) {
        return - 1;
    }

    private byte[] getIV(int seed) {
        // Should be random, but for testing we make it static
        return null;
    }

    private void setKey(String key) {
        this.key = key.getBytes();
    }

    private byte[] getPadding (int lenght) {
        return null;
    }

    private byte[] encryptBlockCBC(byte[] block, byte[] prevBlock){
        byte[] encryptedBlock = new byte[blockSize];

        // Encrypt using caesar variant (shit but irrelevant for POC)
        for (int i = 0; i < blockSize; i++) {
            encryptedBlock[i] = block[i] += key[i];
        }

        // Xor with previous block
        for (int i = 0; i < blockSize; i++) {
            encryptedBlock[i] = (byte) (block[i] ^ prevBlock[i]);
        }
        return encryptedBlock;
    }

    private byte[] encrypt(String data){
        byte[] dataAsByteArray = data.getBytes();

        int numberOfBlocks = (dataAsByteArray.length / blockSize) + 1;

        // Get size of padding that needs to go on last block
        int paddingSize = blockSize - dataAsByteArray.length % blockSize;

        int paddedDataLength = dataAsByteArray.length + paddingSize;
        byte[] paddedData = new byte[paddedDataLength ];

        // Add padding to the last block
        int lastBlockOffset = (numberOfBlocks - 1) * blockSize;
        byte[] padding = getPadding(paddingSize);
        for (int i = lastBlockOffset; i < paddedDataLength; i++){
            paddedData[i] = padding[i - lastBlockOffset];
        }

        byte[] iv = getIV(0);

        for (int i = 0; i < numberOfBlocks; i++) {

        }
        return null;
    }
}