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

    public static void main(String[] args) throws Exception {
        new cbcPkcs7Attack();
    }

    public cbcPkcs7Attack() throws Exception {
        server = new Server(new NormalCBCMode());
        scanner = new Scanner(System.in);

        cipherText = server.getCipherText();

        // make sub arrays for calculations
        // 32 bytes of original encryption encSubArr stays the same and tempEnc is manipulated one byte at a time
        encSubArr = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
        tempEnc = Arrays.copyOfRange(cipherText.clone(), cipherText.length - 2 * blockSize, cipherText.length);
        // array for storing the bytes of the intermediate representation
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
            // position of the byte that is being recovered
            startPos = tempEnc.length - iter;

            if (iter == 1 && block == 1) {
                // first part of the encrypted message is padding
                findPadding(startPos);
                System.out.println("Padding of size " + iter + " is now removed");
                System.out.println("Number of queries made: " + server.getQueries());
                System.out.println("Press enter to continue or say no to exit");
            } else {
                // getNextByte recovers the next byte and adds it in front of the plaintext
                plaintext = getNextByte(startPos, iter) + plaintext;

                System.out.println("Recovered plaintext is now: " + plaintext);
                System.out.println("Number of queries made: " + server.getQueries());
                System.out.println("Press enter to continue or say no to exit");
            }
            iter++;

            if (iter == (blockSize + 1) && block + 1 != numberOfBlocks) {
                // if end of block is reached make new temporary arrays and increase block number (the arrays is just shifted 16 bytes)
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

    /**
     * find padding and make arrays ready for finding next byte
     * @param pos posttion in arrays
     */
    private void findPadding(int pos) throws Exception {

        // get size of padding
        int paddingSize = getPaddingSize(pos);

        // make intermediate array for padding
        for (int j = 0; j < paddingSize; j++) {
            padI[(blockSize - 1) - j] = ((int) padDelta[(blockSize - 1) - j] ^ paddingSize);
        }

        // insert padding intermediates into intermediate array
        System.arraycopy(padI, padI.length - paddingSize, intermediate, intermediate.length - paddingSize, paddingSize);

        // calculate new byte representation for next iteration
        for (int j = 0; j < paddingSize; j++) {
            tempEnc[(blockSize - 1) - j] = (byte) (padI[(blockSize - 1) - j] ^ paddingSize + 1);
        }

        // setting iter to padding size to skip padding
        iter = paddingSize;
    }


    /**
     * Gets next byte from ciphertext by finding which byte from the last block makes a valid padding and setup the last block for next byte
     * @param pos position in arrays
     * @param iteration posistion in block
     * @return res the next plaintext byte in original message
     */
    private String getNextByte(int pos, int iteration) throws Exception {

        String res = "";

        // guess byte to get a valid padding
        for (int i = 0; i < 256; i++) {
            byte[] temp = tempEnc.clone();
            // pos - blocksize is changed to make new byte at pos
            temp[pos - blockSize] = (byte) i;
            if (server.isPaddingCorrect(temp)) {

                // calculate intermediate for pos
                intermediate[pos] = (byte) (i ^ iteration);

                // calculate new byte representation for next iteration
                for (int j = 0; j < iteration; j++) {
                    tempEnc[pos - blockSize + j] = (byte) (intermediate[pos + j] ^ iteration + 1);
                }

                // get original plaintext byte
                res = decrypt((byte) pos, intermediate[pos]);
                break;
            }
        }

        // return recovered plaintext byte
        return res;
    }


    /**
     * Checks padding and returns the size
     * @param pos position in arrays
     * @return paddingSize
     */
    private int getPaddingSize(int pos) throws Exception {
        int paddingSize = 0;

        // changing bytes to byte 17 to see when padding is not valid (starts from the left)
        for (int j = (blockSize - 1); j > -1; j--) {
            byte[] temp = tempEnc.clone();
            temp[pos - blockSize - j] = (byte) (blockSize + 1);

            // if not valid, padding is broken and size is found
            if (!server.isPaddingCorrect(temp)) {
                paddingSize = j + 1;
                break;
            }
        }

        // getting deltas for padding
        for (int j = 0; j < paddingSize; j++) {
            padDelta[(blockSize - 1) - j] = encSubArr[(blockSize - 1) - j];
        }

        return paddingSize;
    }

    /**
     * Returns the plaintext of byte on pos
     * @param pos position in arrays
     * @param inter intermediate byte
     * @return String of plaintext byte
     */
    private String decrypt(int pos, int inter) {
        return new String(new byte[] { (byte) ((int) encSubArr[pos - blockSize] ^ inter) });
    }

}