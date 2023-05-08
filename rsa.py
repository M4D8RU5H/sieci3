from Crypto.Util import number
from Crypto.Util.number import long_to_bytes, bytes_to_long


class RSA:
    def __init__(self, key_size):
        self.key_size = key_size
        self.public_key, self.private_key = self.generate_key_pair()

    def generate_key_pair(self):
        p = number.getPrime(self.key_size // 2)
        q = number.getPrime(self.key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = number.inverse(e, phi)
        return (n, e), (n, d)

    def encrypt_text(self, plaintext):
        plaintext_bytes = plaintext.encode('utf-8')
        block_size = self.key_size // 8
        encrypted_blocks = []
        for i in range(0, len(plaintext_bytes), block_size):
            block = plaintext_bytes[i:i + block_size]
            block_num = bytes_to_long(block)
            encrypted_num = pow(block_num, self.public_key[1], self.public_key[0])
            encrypted_blocks.append(encrypted_num)
        encrypted_bytes = b"".join(long_to_bytes(num, self.key_size // 8) for num in encrypted_blocks)
        return encrypted_bytes

    def decrypt_text(self, ciphertext):
        block_size = self.key_size // 8
        ciphertext_blocks = [bytes_to_long(ciphertext[i:i + block_size]) for i in range(0, len(ciphertext), block_size)]
        decrypted_blocks = []
        for block in ciphertext_blocks:
            decrypted_num = pow(block, self.private_key[1], self.private_key[0])
            decrypted_bytes = decrypted_num.to_bytes((decrypted_num.bit_length() + 7) // 8, 'big')
            decrypted_blocks.append(decrypted_bytes)
        decrypted_bytes = b"".join(decrypted_blocks)
        decrypted_text = decrypted_bytes.decode('utf-8')
        return decrypted_text


plaintext = "To jest tekst do zaszyfrowania"
rsa = RSA(1024)
ciphertext = rsa.encrypt_text(plaintext)
decrypted_text = rsa.decrypt_text(ciphertext)

print("Tekst oryginalny:", plaintext)
print("Zaszyfrowany tekst:", ciphertext)
print("Odszyfrowany tekst:", decrypted_text)
