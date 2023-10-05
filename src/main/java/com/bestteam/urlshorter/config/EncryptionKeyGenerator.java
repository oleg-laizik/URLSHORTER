package com.bestteam.urlshorter.config;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EncryptionKeyGenerator {

    public static void main(String[] args) {
        try {
            int keyLengthInBits = 256; // Change this value as needed (e.g., 128, 256)

            byte[] encryptionKey = generateRandomKey(keyLengthInBits);
            String base64Key = convertToBase64(encryptionKey);
            String hexKey = convertToHex(encryptionKey);

            System.out.println("Generated Encryption Key: " + base64Key);
            System.out.println("Generated Encryption Key Hex: " + hexKey);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error generating encryption key: " + e.getMessage());
        }
    }

    private static byte[] generateRandomKey(int keyLengthInBits) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[keyLengthInBits / 8];
        secureRandom.nextBytes(keyBytes);
        return keyBytes;
    }

    private static String convertToBase64(byte[] keyBytes) {
        return java.util.Base64.getEncoder().encodeToString(keyBytes);
    }

    private static String convertToHex(byte[] keyBytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : keyBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
