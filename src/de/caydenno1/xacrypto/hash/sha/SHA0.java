package de.caydenno1.xacrypto.hash.sha;

import de.caydenno1.xacrypto.misc.Constants;

import java.nio.charset.StandardCharsets;

public class SHA0 {
    // we really only need one file. very simple code
    public static byte[] hash(byte[] data){
        System.out.println("Beware, SHA0 is deprecated and cryptographically broken. Use at your own risk.");
        byte[] padded = pad(data);

        int a0 = Constants.SHA0_H[0], a1 = Constants.SHA0_H[1], a2 = Constants.SHA0_H[2], a3 = Constants.SHA0_H[3], a4 = Constants.SHA0_H[4];

        int[] w = new int[80];

        for (int i = 0 ; i < padded.length ; i += 64) {

            for (int j = 0 ; j < 16 ; j++) {
                int o = i + j * 4;
                w[j] = ((padded[o] & 0xff) << 24)
                        | ((padded[o + 1] & 0xff) << 16)
                        | ((padded[o + 2] & 0xff) << 8)
                        | (padded[o + 3] & 0xff);
            }

            for (int t = 16; t < 80; t++) {
                w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
            }

            int a = a0, b = a1, c = a2, d = a3, e = a4;

            for (int t = 0 ; t < 80 ; t++) {
                int f, k;

                if (t < 20) {
                    f = (b & c);
                    k = Constants.SHA0_K[0];
                } else if (t < 40) {
                    f = b ^ c ^ d;
                    k = Constants.SHA0_K[1];
                } else if (t < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = Constants.SHA0_K[2];
                } else {
                    f = b ^ c ^ d;
                    k = Constants.SHA0_K[3];
                }

                int temp = de.caydenno1.xacrypto.hash.ROT.ROTL(a, 5);
                temp += f;
                temp += e;
                temp += k;
                temp += w[t];

                e = d;
                d = c;
                c = de.caydenno1.xacrypto.hash.ROT.ROTL(b, 30);
                b = a;
                a = temp;
            }

            a0 += a;
            a1 += b;
            a2 += c;
            a3 += d;
            a4 += e;
        }

        return INT2BYTE(a0, a1, a2, a3, a4);
    }

    public static String hash(String data) {
        byte[] result = hash(data.getBytes(StandardCharsets.UTF_8));
        return hex(result);
    }

    public static String hex(byte[] data) {
        StringBuilder builder = new StringBuilder();
        for (byte b : data) builder.append(String.format("%02x", b));
        return builder.toString();
    }

    private static byte[] pad(byte[] mesg) {
        int len = mesg.length;
        long bit = (long) len * 8;

        int padL = (64 - ((len + 9) % 64)) % 64;
        byte[] o = new byte[len+padL+9];

        System.arraycopy(mesg,0,o,0,len);
        o[len] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            o[o.length - (i+1)] = (byte) (bit >>> (8*i));
        }

        return o;
    }

    private static byte[] INT2BYTE(int a,int b,int c,int d,int e) {
        byte[] out = new byte[20];
        write(a, out, 0);
        write(b, out, 4);
        write(c, out, 8);
        write(d, out, 12);
        write(e, out, 16);
        return out;
    }

    private static void write(int v, byte[] o, int i) {
        o[i  ] = (byte)(v >>> 24);
        o[i+1] = (byte)(v >>> 16);
        o[i+2] = (byte)(v >>>  8);
        o[i+3] = (byte)(v       );
    }
}