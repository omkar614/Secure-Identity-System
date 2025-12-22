const { encrypt, decrypt } = require('./encryption');

describe('Encryption Utility', () => {
    
    test('Should encrypt data successfully', () => {
        const secret = "1234-5678-9012";
        const encrypted = encrypt(secret);
        
        // Output should not be equal to input
        expect(encrypted).not.toBe(secret);
        // Output should contain the IV separator
        expect(encrypted).toContain(':');
    });

    test('Should decrypt data back to original value', () => {
        const secret = "MySecretAadhaarNumber";
        const encrypted = encrypt(secret);
        const decrypted = decrypt(encrypted);
        
        expect(decrypted).toBe(secret);
    });

    test('Should handle empty strings correctly', () => {
        expect(encrypt("")).toBe("");
        expect(decrypt("")).toBe("");
    });

    test('Should produce different outputs for same input (Random IV)', () => {
        const secret = "StaticData";
        const enc1 = encrypt(secret);
        const enc2 = encrypt(secret);
        
        // Because of the random IV, two encryptions of the same text should NOT look the same
        expect(enc1).not.toBe(enc2);
        
        // But both should decrypt to the same original text
        expect(decrypt(enc1)).toBe(secret);
        expect(decrypt(enc2)).toBe(secret);
    });
});