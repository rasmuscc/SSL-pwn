import abstractfactories.NormalCBCMode;

import java.util.Arrays;
import java.util.Scanner;

class Client {

    private Server server;
    private byte[] encryption;
    private byte[] fakeEnc;
    private byte[] encSubArr;
    private int[] intermediate;
    private int[] padI = new int[16];
    private byte[] padDelta = new byte[16];
    private Scanner scanner;
    private int iter;
    private int block;

    public static void main(String[] args) {
        new Client();
    }

    private Client() {
        server = new Server(new NormalCBCMode());
        scanner = new Scanner(System.in);

        encryption = server.listen();
        encSubArr = Arrays.copyOfRange(encryption.clone(), encryption.length - 32, encryption.length);
        fakeEnc = Arrays.copyOfRange(encryption.clone(), encryption.length - 32, encryption.length);
        intermediate = new int[encSubArr.length];

        int numberOfBlocks = encryption.length / 16;
        block = 1;

        int startPos;
        iter = 1;

        String plaintext = "";
        System.out.println("Encrypted message: " + new String(encryption));
        System.out.println("First remove padding");
        System.out.println("Press enter to continue or say no to exit");
        while (scanner.hasNextLine()) {
            if (scanner.nextLine().equals("no")) {
                break;
            }
            startPos = fakeEnc.length - iter;
            if (iter == 1 && block == 1) {
                getNextByte(startPos, iter);
                System.out.println("Padding of size " + iter + " is now removed");
                System.out.println("Press enter to continue or say no to exit");
            } else {
                plaintext = getNextByte(startPos, iter) + plaintext;

                System.out.println("Recovered plaintext is now: " + plaintext);
                System.out.println("Press enter to continue or say no to exit");
            }
            iter++;
            if (iter == 17 && block + 1 != numberOfBlocks) {
                block++;
                fakeEnc = Arrays.copyOfRange(encryption.clone(), encryption.length - 16 - (block * 16), encryption.length - ((block - 1) * 16));
                encSubArr = Arrays.copyOfRange(encryption.clone(), encryption.length - 16 - (block * 16), encryption.length - ((block - 1) * 16));
                intermediate = new int[fakeEnc.length];
                iter = 1;
            } else if (iter == 17 && block + 1 == numberOfBlocks) {
                System.out.println("Full plaintext recovered: " + plaintext);
                break;
            }
        }


    }

    private String getNextByte(int pos, int iteration) {

        String res = "";

        for (int i = 0; i < 257; i++) {
            byte[] temp = fakeEnc.clone();
            temp[pos - 16] = (byte) i;
            if (server.isPaddingCorrect(temp)) {

                intermediate[pos] = (byte) ((byte) i ^ (byte) iteration);
                if (intermediate[pos] < 0) {
                    intermediate[pos] += 256;
                }
                padI[15] = (byte) intermediate[pos];
                int paddingSize;
                if (block == 1 && iteration == 1) {
                    paddingSize = checkForPadding(pos, i + 1);
                } else {
                    paddingSize = 0;
                }

                if (paddingSize > 1) {
                    for (int j = 0; j < paddingSize; j++) {
                        padI[15 - j] = (byte) (padDelta[15 - j] ^ (byte) paddingSize);
                    }
                    System.arraycopy(padI, padI.length - paddingSize, intermediate, intermediate.length - paddingSize, paddingSize);
                    fakeEnc = temp;
                    for (int j = 0; j < paddingSize; j++) {
                        fakeEnc[15 - j] = (byte) (padI[15 - j] ^ (byte) paddingSize + 1);
                    }
                    iter = paddingSize;
                    break;
                } else {
                    fakeEnc = temp;
                    for (int j = 0; j < iteration; j++) {
                        if (pos - 16 + j > -1) {
                            fakeEnc[pos - 16 + j] = (byte) (intermediate[pos + j] ^ (byte) iteration + 1);
                        }
                    }
                }
                res = decrypt((byte) pos, intermediate[pos]);
                break;

            }
        }

        return res;
    }

    private int checkForPadding(int pos, int next) {
        int paddingSize = -1;
        boolean escape = false;
        for (int j = 0; j < 16; j++) {
            int start = 1;
            if (j == 0) {
                start = next;
            }
            for (int i = start; i < 257; i++) {
                if (pos - 16 - j > -1) {
                    byte[] temp = fakeEnc.clone();
                    temp[pos - 16 - j] = (byte) i;
                    if (server.isPaddingCorrect(temp)) {
                        paddingSize = j + 1;
                        padDelta[15 - j] = (byte) i;
                        temp[pos - 16 - j] = (byte) 257;
                        if (server.isPaddingCorrect(temp)) {
                            System.out.println(paddingSize);
                            paddingSize--;
                            escape = true;
                            break;
                        }
                        break;
                    }
                    if (i == 256){
                        escape = true;
                    }
                }
            }
            if (escape) {
                if (j == 1) paddingSize = 2;
                break;
            }
        }

        return paddingSize;
    }


    private String decrypt(int pos, int inter) {
        return new String(new byte[] { (byte) (encSubArr[pos - 16] ^ inter) });
    }

}