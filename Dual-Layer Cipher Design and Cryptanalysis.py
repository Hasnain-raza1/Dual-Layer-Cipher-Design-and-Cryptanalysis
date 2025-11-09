import math
from collections import Counter

# ==============================================================================
# 1. CUSTOM CIPHER IMPLEMENTATION
# ==============================================================================

class CustomCipherComplete:
    """
    A complete custom cipher that encrypts letters, numbers, spaces, and hyphens.
    Character set: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789- 
    """
    COMPLETE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789- "
    MODULO = len(COMPLETE_CHARS)
    CHAR_TO_NUM = {c: i for i, c in enumerate(COMPLETE_CHARS)}
    NUM_TO_CHAR = {i: c for i, c in enumerate(COMPLETE_CHARS)}

    def __init__(self, vigenere_key, affine_key):
        if len(vigenere_key) < 10:
            raise ValueError("Vigenère key must be at least 10 characters long.")
        
        self.vigenere_key = vigenere_key.upper()
        self.a, self.b = affine_key
        
        # Validate the Affine key 'a' with the new modulo (38)
        if math.gcd(self.a, self.MODULO) != 1:
            raise ValueError(f"Affine key 'a' must be coprime with {self.MODULO}.")
            
        self.a_inv = pow(self.a, -1, self.MODULO)

    def _vigenere_encrypt(self, plaintext: str) -> str:
        ciphertext = []
        key_index = 0
        for char in plaintext.upper():
            if char in self.COMPLETE_CHARS:
                p = self.CHAR_TO_NUM[char]
                k = self.CHAR_TO_NUM[self.vigenere_key[key_index % len(self.vigenere_key)]]
                c = (p + k) % self.MODULO
                ciphertext.append(self.NUM_TO_CHAR[c])
                key_index += 1
            else:
                ciphertext.append(char)
        return "".join(ciphertext)

    def _vigenere_decrypt(self, ciphertext: str) -> str:
        plaintext = []
        key_index = 0
        for char in ciphertext.upper():
            if char in self.COMPLETE_CHARS:
                c = self.CHAR_TO_NUM[char]
                k = self.CHAR_TO_NUM[self.vigenere_key[key_index % len(self.vigenere_key)]]
                p = (c - k) % self.MODULO
                plaintext.append(self.NUM_TO_CHAR[p])
                key_index += 1
            else:
                plaintext.append(char)
        return "".join(plaintext)

    def _affine_encrypt(self, plaintext: str) -> str:
        ciphertext = []
        for char in plaintext.upper():
            if char in self.COMPLETE_CHARS:
                x = self.CHAR_TO_NUM[char]
                c = (self.a * x + self.b) % self.MODULO
                ciphertext.append(self.NUM_TO_CHAR[c])
            else:
                ciphertext.append(char)
        return "".join(ciphertext)

    def _affine_decrypt(self, ciphertext: str) -> str:
        plaintext = []
        for char in ciphertext.upper():
            if char in self.COMPLETE_CHARS:
                y = self.CHAR_TO_NUM[char]
                x = (self.a_inv * (y - self.b)) % self.MODULO
                plaintext.append(self.NUM_TO_CHAR[x])
            else:
                plaintext.append(char)
        return "".join(plaintext)

    def encrypt(self, plaintext: str) -> str:
        intermediate_text = self._vigenere_encrypt(plaintext)
        ciphertext = self._affine_encrypt(intermediate_text)
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        intermediate_text = self._affine_decrypt(ciphertext)
        plaintext = self._vigenere_decrypt(intermediate_text)
        return plaintext

# ==============================================================================
# 2. SECURITY ANALYSIS AND ATTACK IMPLEMENTATION
# ==============================================================================

class CipherBreaker:
    """
    Implements attacks to break the CustomCipherComplete.
    """
    def __init__(self, known_plaintext, known_ciphertext):
        self.plaintext = known_plaintext.upper()
        self.ciphertext = known_ciphertext.upper()
        # Use the same character set as the cipher
        self.CHARSET = CustomCipherComplete.COMPLETE_CHARS
        self.MODULO = CustomCipherComplete.MODULO
        self.CHAR_TO_NUM = CustomCipherComplete.CHAR_TO_NUM
        self.NUM_TO_CHAR = CustomCipherComplete.NUM_TO_CHAR

    def frequency_analysis_attack(self):
        """
        Attempts to break the cipher using frequency analysis.
        This method is expected to fail against this cipher but demonstrates the technique.
        """
        print("--- [Attack] Frequency Analysis ---")
        print("Analyzing character frequencies in the ciphertext...\n")
        
        # Count frequencies of characters in the ciphertext
        freq = Counter(self.ciphertext)
        total_chars = sum(freq.values())
        
        print("Ciphertext Character Frequencies:")
        for char, count in sorted(freq.items()):
            percentage = (count / total_chars) * 100
            print(f"  {char}: {count} ({percentage:.2f}%)")
        
        print("\n--- Analysis ---")
        print("Frequency analysis is INEFFECTIVE against this cipher.")
        print("Reason: The Vigenère stage flattens the letter frequencies, and the")
        print("Affine stage further scrambles them. The resulting distribution is")
        print("much more uniform than the English language's, providing no useful clues.")
        print("----------------------------------------------------\n")

    def _is_likely_key(self, key_candidate):
        """A heuristic to check if a derived key looks like a real repeating key."""
        if not key_candidate or len(key_candidate) < 10:
            return False
        # Check if the first 10 characters of the key repeat later
        segment = key_candidate[:10]
        return segment in key_candidate[10:]

    def known_plaintext_attack(self):
        """
        Breaks the cipher using a known-plaintext attack by brute-forcing the Affine key.
        """
        print("--- [Attack] Known-Plaintext Attack ---")
        print("Attempting to recover keys by brute-forcing the Affine key...\n")
        
        # Possible values for 'a' in the Affine key (must be coprime with 38)
        possible_a_values = [1, 3, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37]
        
        for a in possible_a_values:
            a_inv = pow(a, -1, self.MODULO)
            for b in range(self.MODULO):
                # --- Step 1: Decrypt ciphertext with candidate Affine key ---
                intermediate_text = ""
                for char_c in self.ciphertext:
                    if char_c in self.CHARSET:
                        y = self.CHAR_TO_NUM[char_c]
                        x = (a_inv * (y - b)) % self.MODULO
                        intermediate_text += self.NUM_TO_CHAR[x]
                
                # --- Step 2: Derive the potential Vigenère key ---
                vigenere_key_candidate = ""
                for i in range(len(self.plaintext)):
                    char_p = self.plaintext[i]
                    if i < len(intermediate_text) and char_p in self.CHARSET:
                        char_i = intermediate_text[i]
                        if char_i in self.CHARSET:
                            p = self.CHAR_TO_NUM[char_p]
                            i_val = self.CHAR_TO_NUM[char_i]
                            k = (i_val - p) % self.MODULO
                            vigenere_key_candidate += self.NUM_TO_CHAR[k]
                
                # --- Step 3: Check if the derived key is plausible ---
                if self._is_likely_key(vigenere_key_candidate):
                    print("SUCCESS! Found potential keys.")
                    print(f"  -> Recovered Affine Key (a, b): ({a}, {b})")
                    print(f"  -> Recovered Vigenère Key: {vigenere_key_candidate[:len(vigenere_key_candidate)//2]}...") # Show a snippet
                    return (a, b), vigenere_key_candidate[:len(vigenere_key_candidate)//2] # Return the base key

        print("FAILURE: Could not determine the keys with the given plaintext.")
        return None, None


# ==============================================================================
# 3. MAIN EXECUTION
# ==============================================================================

if __name__ == "__main__":
    # --- Setup ---
    vigenere_key = "CLASSICALKEY"
    affine_key = (7, 3)  # a=7, b=3 (gcd(7, 38)=1)
    
    # Create the legitimate cipher instance
    cipher = CustomCipherComplete(vigenere_key, affine_key)
    
    # --- Part 1: Simple Encryption/Decryption Demo ---
    plaintext = "HASNAIN RAZA KHAN CR-034"
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Plaintext: {plaintext}")
    print(f"encrypted: {ciphertext}")
    
    decrypted_text = cipher.decrypt(ciphertext)
    print(f"decrypted: {decrypted_text}\n")
    
    # --- Part 2: Security Analysis and Attack Demo ---
    print("--- Security Analysis ---")
    # The attacker now has the known_plaintext and known_ciphertext from above.
    attacker = CipherBreaker(plaintext, ciphertext)
    
    # 1. Attacker tries Frequency Analysis
    attacker.frequency_analysis_attack()
    
    # 2. Attacker tries a Known-Plaintext Attack
    found_affine_key, found_vigenere_key = attacker.known_plaintext_attack()
    
    # --- Using the Recovered Keys ---
    if found_affine_key and found_vigenere_key:
        print("\n--- Attacker using recovered keys on a new message ---")
        # The attacker intercepts a new message
        new_ciphertext = "1Y9GQ3PY2H8WY5J1H2D"
        print(f"Intercepted: {new_ciphertext}")
        
        # The attacker creates a cipher instance with the stolen keys
        attacker_cipher = CustomCipherComplete(found_vigenere_key, found_affine_key)
        
        # And decrypts it
        decrypted_new_message = attacker_cipher.decrypt(new_ciphertext)
        print(f"Decrypted: {decrypted_new_message}")