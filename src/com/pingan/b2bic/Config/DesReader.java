package com.pingan.b2bic.Config;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

/**
 * 密码Des加密读写器
 *
 * @author ywb
 *
 */
public class DesReader implements IPasswordReader {
    private static byte[] pwd = "Pingan01".getBytes();

    private static final String ALGORITHM = "DES";

    private static final String PADDING = "/ECB/PKCS5Padding";

    private static final byte equalSign = (byte) '=';

    /**
     * 密码解密方法，非静态方法
     * <h3>请求示例</h3>
     * String pwd = new DesReader().read(src);<br>
     *
     * @author Anzhi
     * @param  src       加密后字符串
     * @return           解密后字符串
     * @since           2018/06/01
     */
    public String read(String src) {
        if (src == null) {
            return null;
        }
        try {
            byte[] dbase64 = decode(src.getBytes());
            byte[] bsrc = decrypt(dbase64);
            return new String(bsrc);
        } catch (Exception e) {
            throw new RuntimeException("invaild encrypted Filed:" + src, e);
        }
    }

    /**
     * 密码加密方法，非静态方法
     * <h3>请求示例</h3>
     * String pwd = new DesReader().write(src);<br>
     *
     * @author Anzhi
     * @param  src       待加密字符串
     * @return           加密后字符串
     * @since           2018/06/01
     */
    public String write(String src) {
        if (src == null) {
            return null;
        }
        try {
            byte[] bencry = encrypt(src.getBytes());
            byte[] ebase64 = encode(bencry);
            return new String(ebase64);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * 数据加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    private static byte[] encrypt(byte[] data) throws Exception {
        DESKeySpec desKeySpec = new DESKeySpec(pwd);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey deskey = keyFactory.generateSecret(desKeySpec);
        Cipher c = Cipher.getInstance(deskey.getAlgorithm() + PADDING);
        c.init(Cipher.ENCRYPT_MODE, deskey);
        byte[] bRet = c.doFinal(data);
        return bRet;
    }

    /**
     * 数据解密
     *
     */
    private static byte[] decrypt(byte[] data) throws Exception {
        DESKeySpec desKeySpec = new DESKeySpec(pwd);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey deskey = keyFactory.generateSecret(desKeySpec);
        Cipher c = Cipher.getInstance(deskey.getAlgorithm() + PADDING);
        c.init(Cipher.DECRYPT_MODE, deskey);
        byte[] bRet = c.doFinal(data);
        return bRet;
    }

    static char digits[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M',
            'N',
            'O',
            'P', //
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd',
            'e',
            'f', //
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
            't', 'u',
            'v', //
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', '+', '/' };

    /**
     * This method decodes the byte array in base 64 encoding into a char array
     * Base 64 encoding has to be according to the specification given by the
     * RFC 1521 (5.2).
     *
     * @param data
     *            the encoded byte array
     * @return the decoded byte array
     */
    private static byte[] decode(byte[] data) {
        if (data.length == 0)
            return data;
        int lastRealDataIndex = data.length - 1;
        while (data[lastRealDataIndex] == equalSign)
            lastRealDataIndex--;
        // original data digit is 8 bits long, but base64 digit is 6 bits long
        int padBytes = data.length - 1 - lastRealDataIndex;
        int byteLength = data.length * 6 / 8 - padBytes;
        byte[] result = new byte[byteLength];
        // Each 4 bytes of input (encoded) we end up with 3 bytes of output
        int dataIndex = 0;
        int resultIndex = 0;
        int allBits = 0;
        // how many result chunks we can process before getting to pad bytes
        int resultChunks = (lastRealDataIndex + 1) / 4;
        for (int i = 0; i < resultChunks; i++) {
            allBits = 0;
            // Loop 4 times gathering input bits (4 * 6 = 24)
            for (int j = 0; j < 4; j++)
                allBits = (allBits << 6) | decodeDigit(data[dataIndex++]);
            // Loop 3 times generating output bits (3 * 8 = 24)
            for (int j = resultIndex + 2; j >= resultIndex; j--) {
                result[j] = (byte) (allBits & 0xff); // Bottom 8 bits
                allBits = allBits >>> 8;
            }
            resultIndex += 3; // processed 3 result bytes
        }
        // Now we do the extra bytes in case the original (non-encoded) data
        // was not multiple of 3 bytes
        switch (padBytes) {
            case 1:
                // 1 pad byte means 3 (4-1) extra Base64 bytes of input, 18
                // bits, of which only 16 are meaningful
                // Or: 2 bytes of result data
                allBits = 0;
                // Loop 3 times gathering input bits
                for (int j = 0; j < 3; j++)
                    allBits = (allBits << 6) | decodeDigit(data[dataIndex++]);
                // NOTE - The code below ends up being equivalent to allBits =
                // allBits>>>2
                // But we code it in a non-optimized way for clarity
                // The 4th, missing 6 bits are all 0
                allBits = allBits << 6;
                // The 3rd, missing 8 bits are all 0
                allBits = allBits >>> 8;
                // Loop 2 times generating output bits
                for (int j = resultIndex + 1; j >= resultIndex; j--) {
                    result[j] = (byte) (allBits & 0xff); // Bottom 8
                    // bits
                    allBits = allBits >>> 8;
                }
                break;
            case 2:
                // 2 pad bytes mean 2 (4-2) extra Base64 bytes of input, 12 bits
                // of data, of which only 8 are meaningful
                // Or: 1 byte of result data
                allBits = 0;
                // Loop 2 times gathering input bits
                for (int j = 0; j < 2; j++)
                    allBits = (allBits << 6) | decodeDigit(data[dataIndex++]);
                // NOTE - The code below ends up being equivalent to allBits =
                // allBits>>>4
                // But we code it in a non-optimized way for clarity
                // The 3rd and 4th, missing 6 bits are all 0
                allBits = allBits << 6;
                allBits = allBits << 6;
                // The 3rd and 4th, missing 8 bits are all 0
                allBits = allBits >>> 8;
                allBits = allBits >>> 8;
                result[resultIndex] = (byte) (allBits & 0xff); // Bottom
                // 8
                // bits
                break;
        }
        return result;
    }

    /**
     * This method converts a Base 64 digit to its numeric value.
     *
     * @param data
     *            digit (character) to convert
     * @return value for the digit
     */
    private static int decodeDigit(byte data) {
        char charData = (char) data;
        if (charData <= 'Z' && charData >= 'A')
            return charData - 'A';
        if (charData <= 'z' && charData >= 'a')
            return charData - 'a' + 26;
        if (charData <= '9' && charData >= '0')
            return charData - '0' + 52;
        switch (charData) {
            case '+':
                return 62;
            case '/':
                return 63;
            default:
                throw new IllegalArgumentException(
                        "Invalid char to decode: " + data); //$NON-NLS-1$
        }
    }

    /**
     * This method encodes the byte array into a char array in base 64 according
     * to the specification given by the RFC 1521 (5.2).
     *
     * @param data
     *            the encoded char array
     * @return the byte array that needs to be encoded
     */
    private static byte[] encode(byte[] data) {
        int sourceChunks = data.length / 3;
        int len = ((data.length + 2) / 3) * 4;
        byte[] result = new byte[len];
        int extraBytes = data.length - (sourceChunks * 3);
        // Each 4 bytes of input (encoded) we end up with 3 bytes of output
        int dataIndex = 0;
        int resultIndex = 0;
        int allBits = 0;
        for (int i = 0; i < sourceChunks; i++) {
            allBits = 0;
            // Loop 3 times gathering input bits (3 * 8 = 24)
            for (int j = 0; j < 3; j++)
                allBits = (allBits << 8) | (data[dataIndex++] & 0xff);
            // Loop 4 times generating output bits (4 * 6 = 24)
            for (int j = resultIndex + 3; j >= resultIndex; j--) {
                result[j] = (byte) digits[(allBits & 0x3f)]; // Bottom
                // 6
                // bits
                allBits = allBits >>> 6;
            }
            resultIndex += 4; // processed 4 result bytes
        }
        // Now we do the extra bytes in case the original (non-encoded) data
        // is not multiple of 4 bytes
        switch (extraBytes) {
            case 1:
                allBits = data[dataIndex++]; // actual byte
                allBits = allBits << 8; // 8 bits of zeroes
                allBits = allBits << 8; // 8 bits of zeroes
                // Loop 4 times generating output bits (4 * 6 = 24)
                for (int j = resultIndex + 3; j >= resultIndex; j--) {
                    result[j] = (byte) digits[(allBits & 0x3f)]; // Bottom
                    // 6
                    // bits
                    allBits = allBits >>> 6;
                }
                // 2 pad tags
                result[result.length - 1] = (byte) '=';
                result[result.length - 2] = (byte) '=';
                break;
            case 2:
                allBits = data[dataIndex++]; // actual byte
                allBits = (allBits << 8) | (data[dataIndex++] & 0xff); // actual
                // byte
                allBits = allBits << 8; // 8 bits of zeroes
                // Loop 4 times generating output bits (4 * 6 = 24)
                for (int j = resultIndex + 3; j >= resultIndex; j--) {
                    result[j] = (byte) digits[(allBits & 0x3f)]; // Bottom
                    // 6
                    // bits
                    allBits = allBits >>> 6;
                }
                // 1 pad tag
                result[result.length - 1] = (byte) '=';
                break;
        }
        return result;
    }

//    public static void main(String[] args) {
//        String pwd = "12345678";
//        String pss="m3bZThcNLdE=";
//        System.out.println(new DesReader().write(pwd));
//        System.out.println(new DesReader().read(pss));
//    }
}

