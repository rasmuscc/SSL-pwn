import abstractfactories.NormalCBCMode;

import java.util.Arrays;
import java.util.Scanner;

class cbcPkcs7Attack {

    private Server server;
    private byte[] cipherText;
    private byte[] tempEnc;
    private byte[] encSubArr;
    private int blockSize = 16;
    private int[] intermediate;
    private int[] padI = new int[blockSize];
    private byte[] padDelta = new byte[blockSize];
    private Scanner scanner;
    private int iter;
    private int block;

    public static void main(String[] args) {
        new cbcPkcs7Attack();
    }

    public cbcPkcs7Attack() {
        server = new Server(new NormalCBCMode());
        scanner = new Scanner(System.in);

        cipherText = server.getCipherText();

        // make sub arrays for calculations
        encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
        tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);

        intermediate = new int[encSubArr.length];

        int numberOfBlocks = cipherText.length / blockSize;
        block = 1;

        int startPos;
        iter = 1;

        // begin plaintext recovery
        String plaintext = "";
        System.out.println("Encrypted message: " + new String(cipherText));
        System.out.println("First remove padding");
        System.out.println("Press enter to continue or say no to exit");
        while (scanner.hasNextLine()) {
            if (scanner.nextLine().equals("no")) {
                break;
            }
            startPos = tempEnc.length - iter;

            if (iter == 1 && block == 1) {
                // first find out size of padding
                getNextByte(startPos, iter);
                System.out.println("Padding of size " + iter + " is now removed");
                System.out.println("Press enter to continue or say no to exit");
            } else {
                // update plaintext with next byte
                plaintext = getNextByte(startPos, iter) + plaintext;

                System.out.println("Recovered plaintext is now: " + plaintext);
                System.out.println("Press enter to continue or say no to exit");
            }
            iter++;

            if (iter == (blockSize + 1) && block + 1 != numberOfBlocks) {
                // if end of block is reached make new temporary arrays and increase block number
                block++;
                tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - blockSize - (block * blockSize), cipherText.length - ((block - 1) * blockSize));
                encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - blockSize - (block * blockSize), cipherText.length - ((block - 1) * blockSize));
                intermediate = new int[tempEnc.length];
                // start over for next block
                iter = 1;
            } else if (iter == (blockSize + 1) && block + 1 == numberOfBlocks) {
                // terminate if all blocks have been decrypted
                System.out.println("Full plaintext recovered: " + plaintext);
                break;
            }
        }
    }

    private String getNextByte(int pos, int iteration) {

        String res = "";
        // check padding first
        if (block == 1 && iteration == 1) {

            // get size of padding
            int paddingSize = getPaddingSize(pos);

            // make intermediate array for padding
            for (int j = 0; j < paddingSize; j++) {
                padI[(blockSize - 1) - j] = (byte) (padDelta[(blockSize - 1) - j] ^ (byte) paddingSize);
            }

            // insert padding intermediates into intermediate array
            System.arraycopy(padI, padI.length - paddingSize, intermediate, intermediate.length - paddingSize, paddingSize);

            // calculate new byte representation for next iteration
            for (int j = 0; j < paddingSize; j++) {
                tempEnc[(blockSize - 1) - j] = (byte) (padI[(blockSize - 1) - j] ^ (byte) paddingSize + 1);
            }

            // setting iter to padding size to skip padding
            iter = paddingSize;
        } else {
            // guess byte to get a valid padding
            for (int i = 0; i < 256; i++) {
                byte[] temp = tempEnc.clone();
                temp[pos - blockSize] = (byte) i;

                if (server.isPaddingCorrect(temp)) {

                    // calculate intermediate for pos
                    intermediate[pos] = (byte) ((byte) i ^ (byte) iteration);

                    // calculate new byte representation for next iteration
                    for (int j = 0; j < iteration; j++) {
                        tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ (byte) iteration + 1);
                    }

                    // get original plaintext byte
                    res = decrypt((byte) pos, intermediate[pos]);
                    break;
                }
            }
        }

        return res;
    }


    /**
     * Checks padding and returns the size
     * @param pos position in arrays
     * @return paddingSize
     */
    private int getPaddingSize(int pos) {
        int paddingSize = 0;

        // changing bytes to something illegal to see when padding is not valid
        for (int j = (blockSize - 1); j > -1; j--) {
            byte[] temp = tempEnc.clone();
            temp[pos - blockSize - j] = (byte) 257;

            // if not valid padding is broken and size is found
            if (!server.isPaddingCorrect(temp)) {
                paddingSize = j + 1;
                break;
            }
        }

        // getting deltas for padding
        for (int j = 0; j < paddingSize; j++) {
            for (int i = 0; i < 257; i++) {
                byte[] temp = tempEnc.clone();
                temp[pos - blockSize - j] = (byte) i;

                // if valid then delta is i
                if (server.isPaddingCorrect(temp)) {
                    padDelta[(blockSize - 1) - j] = (byte) i;
                    break;
                }
            }
        }

        return paddingSize;
    }


    private String decrypt(int pos, int inter) {
        return new String(new byte[] { (byte) (encSubArr[pos - blockSize] ^ inter) });
    }

}