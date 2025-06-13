package it.bstz.encryption;


import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

@Component
public class EncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public String encryptValue(String key, String value) throws EncryptionException {
        validateInputs(key, value);

        try {
            byte[] iv = deriveIVFromInput(key + value);
            SecretKeySpec secretKey = deriveSecretKey(key);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));

            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(result);

        } catch (Exception e) {
            throw new EncryptionException("Failed to encrypt value", e);
        }
    }

    public String decryptValue(String key, String encryptedValue) throws EncryptionException {
        validateInputs(key, encryptedValue);

        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedValue);

            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[decoded.length - GCM_IV_LENGTH];
            System.arraycopy(decoded, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(decoded, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

            SecretKeySpec secretKey = deriveSecretKey(key);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new EncryptionException("Failed to decrypt value", e);
        }
    }

    private void validateInputs(String key, String value) throws EncryptionException {
        if (key == null || key.trim().isEmpty()) {
            throw new EncryptionException("Key cannot be null or empty");
        }
        if (value == null || value.trim().isEmpty()) {
            throw new EncryptionException("Value cannot be null or empty");
        }
    }

    private SecretKeySpec deriveSecretKey(String key) throws EncryptionException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(key.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(hash, 0, 32, "AES");
        } catch (Exception e) {
            throw new EncryptionException("Failed to derive secret key", e);
        }
    }

    private byte[] deriveIVFromInput(String input) throws EncryptionException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(hash, GCM_IV_LENGTH);
        } catch (Exception e) {
            throw new EncryptionException("Failed to derive IV", e);
        }
    }
}


class EncryptionException extends Exception {
    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
