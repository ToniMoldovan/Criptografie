def vigenere_encrypt(plaintext, key):
    key_len = len(key)
    key_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''

    for i in range(len(plaintext_int)):
        # Encrypt each character by adding its ASCII value to the ASCII value of the corresponding key character
        value = (plaintext_int[i] + key_int[i % key_len]) % 26
        # Convert the encrypted value back to a character and add it to the ciphertext
        ciphertext += chr(value + 65)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """
    Decrypts the given ciphertext using the Vigenère cipher with the given key.

    Args:
        ciphertext (str): The ciphertext to decrypt.
        key (str): The key to use for the decryption.

    Returns:
        str: The decrypted plaintext.
    """
    key_len = len(key)
    key_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        # Decrypt each character by subtracting its ASCII value from the ASCII value of the corresponding key character
        value = (ciphertext_int[i] - key_int[i % key_len]) % 26
        # Convert the decrypted value back to a character and add it to the plaintext
        plaintext += chr(value + 65)
    return plaintext

if __name__ == "__main__":
    key = "abc"
    plainText = "salutare"

    print("Plain text: " + plainText.upper() + "\tKey: " + key.upper())

    encrypted_text = vigenere_encrypt(plainText.upper(), key.upper())
    print("Encrypted text: " + encrypted_text + "\tKey: " + key.upper())

    decrypted_text = vigenere_decrypt(encrypted_text.upper(), key.upper())
    print("Decrypted text: " + decrypted_text + "\tKey: " + key.upper())
