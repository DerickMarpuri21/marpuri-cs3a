import streamlit as st
st.header("XOR CIPHER")

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        
        xor_result = plaintext_byte ^ key_byte
        st.write(f"Plaintext byte:",format(plaintext_byte,'08b'), "=", chr(plaintext_byte))
        st.write(f"Key byte:      ",format(key_byte, '08b'), "=", chr(key_byte))
        st.write(f"XOR result:    ",format(xor_result, '08b'), "=", chr(xor_result))
        st.write("--------------------")
        ciphertext.append(xor_result)
    return ciphertext
        

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption


# Example usage:
plaintext = bytes(st.text_input("Plaintext").encode())
key = bytes(st.text_input("Key").encode())

if st.button("Submit"):
    if not key:
        st.error("invalid key")
    else:
        if plaintext != key:
            if len(plaintext.decode()) >= len(key.decode()):
                ciphertext = xor_encrypt(plaintext, key)
                st.write("Cipher:", ciphertext.decode())

                decrypted = xor_decrypt(ciphertext, key)
                st.write("Decrypted:", decrypted.decode())
            else:
                st.write(f"Plaintext length should be equal or greater than the lenght of key")

        else:
            st.write(f"plaintext should not be equal to the key")
    st.balloons()


