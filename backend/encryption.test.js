const { encrypt, decrypt } = require('./encryption');
const crypto = require('crypto');

describe('Security: AES-256 Encryption Utility', () => {
    
    // 1. Basic Functionality
    test('Happy Path: Should encrypt and decrypt a standard string', () => {
        const originalText = "1234-5678-9012";
        const encrypted = encrypt(originalText);
        const decrypted = decrypt(encrypted);
        
        expect(decrypted).toBe(originalText);
    });

    // 2. Security Check: Randomization
    test('Security: Should produce different ciphertexts for the same input (Random IV)', () => {
        const secret = "StaticSecretData";
        const attempt1 = encrypt(secret);
        const attempt2 = encrypt(secret);
        
        // This proves that a random IV (Initialization Vector) is being used
        // If these were equal, the encryption would be insecure (ECB mode vulnerability)
        expect(attempt1).not.toBe(attempt2);
        
        // But both should still decrypt to the original
        expect(decrypt(attempt1)).toBe(secret);
        expect(decrypt(attempt2)).toBe(secret);
    });

    // 3. Format Validation
    test('Format: Encrypted string should contain IV separator (:)', () => {
        const encrypted = encrypt("Test");
        expect(encrypted).toContain(':');
        
        const parts = encrypted.split(':');
        expect(parts.length).toBe(2); // [IV, Content]
    });

    // 4. Edge Cases: Special Characters
    test('Edge Case: Should handle special characters and emojis', () => {
        const specialText = "P@ssw0rd! with symbols #$%^&*() and emojis 🔒🚀";
        const encrypted = encrypt(specialText);
        const decrypted = decrypt(encrypted);
        
        expect(decrypted).toBe(specialText);
    });

    // 5. Edge Cases: Empty or Null
    test('Edge Case: Should handle empty strings gracefully', () => {
        expect(encrypt("")).toBe("");
        expect(decrypt("")).toBe("");
        expect(encrypt(null)).toBe(null);
    });

    // 6. Integrity Check
    test('Integrity: Tampered ciphertext should fail decryption or return garbage', () => {
        const original = "SensitiveData";
        const encrypted = encrypt(original);
        
        // Tamper with the encrypted part (change last character)
        const tampered = encrypted.substring(0, encrypted.length - 1) + "0";
        
        // Decryption should throw an error OR return incorrect data depending on padding
        // In Node crypto, this usually throws an 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt'
        try {
            const result = decrypt(tampered);
            expect(result).not.toBe(original);
        } catch (error) {
            expect(error).toBeDefined(); // Error is good here, it means tampering was detected
        }
    });
});