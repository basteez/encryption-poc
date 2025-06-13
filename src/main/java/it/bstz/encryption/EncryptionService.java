package it.bstz.encryption;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Service
@Slf4j
public class EncryptionService {
    public String encryptAccountNumber(String sessionId, String accountNumber) throws Exception {
        Cipher cipher = createCipher(sessionId, Cipher.ENCRYPT_MODE);
        byte[] encrypted = cipher.doFinal(accountNumber.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decryptAccountNumber(String sessionId, String encryptedAccountNumber) throws Exception {
        Cipher cipher = createCipher(sessionId, Cipher.DECRYPT_MODE);
        byte[] decoded = Base64.getDecoder().decode(encryptedAccountNumber);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private Cipher createCipher(String sessionId, int mode) throws Exception {
        SecretKeySpec secretKey = deriveKeyFromSessionId(sessionId);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(mode, secretKey);
        return cipher;
    }

    private SecretKeySpec deriveKeyFromSessionId(String sessionId) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sessionId.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(hash, "AES");
    }
}
