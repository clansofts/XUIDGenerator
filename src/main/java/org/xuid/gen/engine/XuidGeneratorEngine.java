/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.xuid.gen.engine;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 *
 * @author clansofts
 */
public class XuidGeneratorEngine {

    private static final int SESS_NUM_CHARS = 32;
    private static final String chars = "KLMNOPQRSTUVWXYZcdefghijklmnop0129abqrstuvwxyz345678ABCDEFGHIJ";
    private static final String passchars = "KLMNOPQRSTUVWXYZcdefghijk$#*@&?lmnop0129abqrstuvwxyz345678ABCDEFGHIJ";
    private static final String numericPass = "0123456789";
    private static final Random r = new Random();
    private static final String TRANSACTION_ALPHAS = "KLMNOPQRSTUVWXYZABCDEFGHIJ";
    private static final String TRANSACTION_NUMS = "0123456789";
    //Transaction Generators {XX0000}

    /**
     *
     * @return Method to generate a unique sessionID that is MD5 hashed
     */
    public static String getUniqueSessionID() {

        char[] buf = new char[SESS_NUM_CHARS];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = chars.charAt(r.nextInt(chars.length()));
        }

        String uniqueSessID = new String(buf);

        return MD5(uniqueSessID);
    }

    /**
     *
     * @param passwordLength the length of the password you want to generate
     * @return Method to Generate a Unique Random Password of the given length
     */
    public static String generateUniquePassword(Integer passwordLength) {
        char[] buf = new char[passwordLength];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = passchars.charAt(r.nextInt(passchars.length()));
        }

        String uniquePassword = new String(buf);

        return uniquePassword;
    }

    /**
     * Method to generate an MD5 hashed string
     *
     * @param md5
     * @return
     */
    public static String MD5(String md5) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] array = md.digest(md5.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < array.length; ++i) {
                sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
        }
        return null;
    }

    /**
     *
     * @param password you want to apply SHA-256 hash on
     * @return SHA-Hashing password with SHA 256
     * @throws NoSuchAlgorithmException
     */
    public static String SHAHashPassword(String password) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());

        byte byteData[] = md.digest();

        //convert the byte to hex format method
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < byteData.length; i++) {
            String hex = Integer.toHexString(0xff & byteData[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    /**
     *
     * @param transactionCodeLength The length of the Transaction Code you want
     * to Generate
     * @return Method to generate a unique transaction code of the length given
     */
    public static String generateUniqueTransactionCode(Integer transactionCodeLength) {
        char[] buf = new char[transactionCodeLength];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = chars.charAt(r.nextInt(chars.length()));
        }

        String uniqueSessID = new String(buf);

        return uniqueSessID;
    }

    /**
     *
     * @param passwordLength the length of the password you want to generate
     * @return Method to Generate a Unique Random Numeric Password of the given
     * length
     */
    public static String generateUniqueNumericPassword(Integer passwordLength) {
        char[] buf = new char[passwordLength];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = numericPass.charAt(r.nextInt(numericPass.length()));
        }

        String uniquePassword = new String(buf);

        return uniquePassword;
    }

    /**
     *
     * @param transCodeLength
     * @return Generating a Transaction code with Two digits and other Numerics
     */
    public static String generateUniqueTransCode(Integer transCodeLength) {

        Integer alphaSize = 2;
        Integer numsSize = (transCodeLength - alphaSize);

        char[] bufAlphas = new char[alphaSize];
        char[] bufNums = new char[numsSize];

        //generating the First Part of the Code
        for (int x = 0; x < bufAlphas.length; x++) {

            bufAlphas[x] = TRANSACTION_ALPHAS.charAt(r.nextInt(TRANSACTION_ALPHAS.length()));
        }

        String uniqueFirstPart = new String(bufAlphas);

        for (int i = 0; i < bufNums.length; i++) {
            bufNums[i] = TRANSACTION_NUMS.charAt(r.nextInt(TRANSACTION_NUMS.length()));
        }

        String uniqueSecondPart = new String(bufNums);

        String uniqueCode = (uniqueFirstPart + uniqueSecondPart);

        return uniqueCode;
    }
}
