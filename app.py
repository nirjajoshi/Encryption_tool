from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish
from Crypto.Random import get_random_bytes
import base64
import streamlit as st

# RSA Encryption and Decryption
def encrypt_rsa(plaintext, public_key):
    try:
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_rsa(ciphertext, private_key):
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

# AES Encryption and Decryption
def pad(data):
    while len(data) % 16 != 0:
        data += b'\0'  # Add padding
    return data

def unpad(data):
    return data.rstrip(b'\0')  # Remove padding

def encrypt_aes(plaintext, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'))
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_aes(ciphertext, key):
    if key is None or ciphertext is None:
        st.error("Key or ciphertext cannot be None.")
        return None
    try:
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]  # Extract the IV from the ciphertext
        ciphertext = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext).decode('utf-8')
        return plaintext
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

# Blowfish Encryption and Decryption
def pad_blowfish(data):
    while len(data) % 8 != 0:
        data += b'\0'  # Pad with null bytes
    return data

def unpad_blowfish(data):
    return data.rstrip(b'\0')  # Remove padding

def encrypt_blowfish(plaintext, key):
    try:
        key = key.encode('utf-8')  # Convert to bytes
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv  # Get the IV
        padded_data = pad_blowfish(plaintext.encode('utf-8'))
        ciphertext = iv + cipher.encrypt(padded_data)  # Prepend IV to ciphertext
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        st.error(f"Blowfish Encryption error: {str(e)}")
        return None

def decrypt_blowfish(ciphertext, key):
    try:
        raw = base64.b64decode(ciphertext)
        iv = raw[:8]  # Extract the IV
        key = key.encode('utf-8')  # Convert to bytes
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plaintext = unpad_blowfish(cipher.decrypt(raw[8:])).decode('utf-8')  # Decrypt and unpad
        return plaintext
    except Exception as e:
        st.error(f"Blowfish Decryption error: {str(e)}")
        return None

# Generate Random AES Key
def generate_aes_key(size):
    return get_random_bytes(size)

# Generate RSA Keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

# Generate Random Blowfish Key
def generate_blowfish_key(size):
    return get_random_bytes(size)

# Streamlit UI
def main():
    st.title("Encryption Tool")

    # Tool Selection
    tool = st.selectbox("Select Encryption Tool", ["Select Tool", "RSA", "AES", "Blowfish"])

    if tool == "RSA":
        # Button to generate RSA keys
        if st.button("Generate RSA Keys"):
            private_key, public_key = generate_rsa_keys()
            st.session_state.private_key = private_key  # Store in session state
            st.session_state.public_key = public_key    # Store in session state

        # Display keys with copy buttons
        if 'public_key' in st.session_state:
            st.subheader("Generated Public Key")
            public_key_area = st.text_area("Public Key", st.session_state.public_key, height=150)

            # Button for copying public key
            if st.button("Copy Public Key"):
                st.success("Public Key copied to clipboard!")
                st.markdown(f"<script>navigator.clipboard.writeText(`{public_key_area}`);</script>", unsafe_allow_html=True)

        if 'private_key' in st.session_state:
            st.subheader("Generated Private Key")
            private_key_area = st.text_area("Private Key", st.session_state.private_key, height=150)

            # Button for copying private key
            if st.button("Copy Private Key"):
                st.success("Private Key copied to clipboard!")
                st.markdown(f"<script>navigator.clipboard.writeText(`{private_key_area}`);</script>", unsafe_allow_html=True)

        # RSA Input for encryption/decryption
        action = st.selectbox("Select RSA Action", ["Select Action", "Encrypt", "Decrypt"])

        message = st.text_area("Enter Message")
        public_key_input = st.text_area("Enter Public Key (for RSA Encryption)", "")
        private_key_input = st.text_area("Enter Private Key (for RSA Decryption)", "")
        
        if st.button("Submit"):
            result = ""
            if action == "Encrypt" and public_key_input:
                result = encrypt_rsa(message, public_key_input)
                if result:
                    st.text_area("Encrypted Message (Base64)", result)
            elif action == "Decrypt" and private_key_input:
                result = decrypt_rsa(message, private_key_input)
                if result:
                    st.text_area("Decrypted Message", result)

    elif tool == "AES":
        key_size = st.selectbox("Select AES Key Size", [128, 192, 256])
        key_length = key_size // 8
        
        # AES Key Generation and Management
        if 'aes_key' not in st.session_state:
            st.session_state.aes_key = None  # Initialize key in session state

        action = st.selectbox("Select AES Action", ["Encrypt", "Decrypt"])

        iv = get_random_bytes(16)  # Generate IV for AES
        st.text_area("Generated IV", iv.hex(), height=150)

        message = st.text_area("Enter Message")
        
        if st.button("Generate Key"):
            st.session_state.aes_key = generate_aes_key(key_length)
            st.text_area("Generated AES Key", st.session_state.aes_key.hex(), height=150)

        if st.button("Submit"):
            result = ""
            if action == "Encrypt" and st.session_state.aes_key and message:
                result = encrypt_aes(message, st.session_state.aes_key, iv)
                if result:
                    st.text_area("Encrypted AES Message (Base64)", result)

            elif action == "Decrypt" and message:
                if st.session_state.aes_key is None:
                    st.error("AES Key must be generated first for decryption.")
                else:
                    result = decrypt_aes(message, st.session_state.aes_key)
                    if result:
                        st.text_area("Decrypted AES Message", result)

    elif tool == "Blowfish":
        key_size = st.selectbox("Select Blowfish Key Size (bits)", [32, 64, 128, 192, 256, 448])
        action = st.selectbox("Select Blowfish Action", ["Encrypt", "Decrypt"])

        message = st.text_area("Enter Message")
        
        # Button to generate Blowfish key
        if st.button("Generate Blowfish Key"):
            blowfish_key = generate_blowfish_key(key_size // 8)
            st.session_state.blowfish_key = blowfish_key.hex()  # Store key in session state
            st.text_area("Generated Blowfish Key", st.session_state.blowfish_key, height=150)

        key = st.text_input("Enter Blowfish Key (must match selected size)", type="password", value=st.session_state.get('blowfish_key', ''))

        if st.button("Submit"):
            result = ""
            if action == "Encrypt" and key:
                result = encrypt_blowfish(message, key)
                if result:
                    st.text_area("Encrypted Blowfish Message (Base64)", result)
        
            elif action == "Decrypt" and key and message:
                result = decrypt_blowfish(message, key)
                if result:
                    st.text_area("Decrypted Blowfish Message", result)

if __name__ == "__main__":
    main()
