package it.bstz.encryption;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class EncryptionServiceTest {
    private final EncryptionService encryptionService = new EncryptionService();

    @Test
    void testEncryptValue_DeterministicOutput() throws Exception {
        String sessionId = "test-session";
        String accountNumber = "1234567890";
        String encrypted1 = encryptionService.encryptValue(sessionId, accountNumber);
        String encrypted2 = encryptionService.encryptValue(sessionId, accountNumber);
        System.out.println("[DeterministicOutput] Encrypted1: " + encrypted1);
        System.out.println("[DeterministicOutput] Encrypted2: " + encrypted2);
        assertEquals(encrypted1, encrypted2, "Encryption should be deterministic for same input");
    }

    @Test
    void testEncryptValue_DifferentSessionId() throws Exception {
        String accountNumber = "1234567890";
        String encrypted1 = encryptionService.encryptValue("session1", accountNumber);
        String encrypted2 = encryptionService.encryptValue("session2", accountNumber);
        System.out.println("[DifferentSessionId] Encrypted1: " + encrypted1);
        System.out.println("[DifferentSessionId] Encrypted2: " + encrypted2);
        assertNotEquals(encrypted1, encrypted2, "Different sessionIds should produce different ciphertexts");
    }

    @Test
    void testEncryptAccountNumber_DifferentValue() throws Exception {
        String sessionId = "test-session";
        String encrypted1 = encryptionService.encryptValue(sessionId, "1111111111");
        String encrypted2 = encryptionService.encryptValue(sessionId, "2222222222");
        System.out.println("[DifferentAccountNumber] Encrypted1: " + encrypted1);
        System.out.println("[DifferentAccountNumber] Encrypted2: " + encrypted2);
        assertNotEquals(encrypted1, encrypted2, "Different account numbers should produce different ciphertexts");
    }

    @Test
    void testDecryptValue_CorrectDecryption() throws Exception {
        String sessionId = "test-session";
        String accountNumber = "1234567890";
        String encrypted = encryptionService.encryptValue(sessionId, accountNumber);
        String decrypted = encryptionService.decryptValue(sessionId, encrypted);
        System.out.println("[Decrypt] Encrypted: " + encrypted);
        System.out.println("[Decrypt] Decrypted: " + decrypted);
        assertEquals(accountNumber, decrypted, "Decryption should return the original account number");
    }

    @Test
    void testDecryptValue_WrongSessionId() throws Exception {
        String sessionId = "test-session";
        String wrongSessionId = "wrong-session";
        String accountNumber = "1234567890";
        String encrypted = encryptionService.encryptValue(sessionId, accountNumber);
        Exception exception = assertThrows(Exception.class, () -> {
            encryptionService.decryptValue(wrongSessionId, encrypted);
        });
        System.out.println("[DecryptWrongSession] Exception: " + exception.getMessage());
    }

    @Test
    void testEncryptDecrypt_FullFlow() throws Exception {
        String sessionId = "flow-session";
        String accountNumber = "0987654321";
        String encrypted = encryptionService.encryptValue(sessionId, accountNumber);
        String decrypted = encryptionService.decryptValue(sessionId, encrypted);
        System.out.println("[FullFlow] Encrypted: " + encrypted);
        System.out.println("[FullFlow] Decrypted: " + decrypted);
        assertEquals(accountNumber, decrypted, "Full flow should return the original account number");
    }
}
