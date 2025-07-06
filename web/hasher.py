import hashlib
import os
import binascii

def scrypt_hash_password(password: str, N=32768, r=8, p=1, dklen=64):
    # Salt erzeugen (z. B. 16 Byte)
    salt = os.urandom(16)
    
    # scrypt-Hash erzeugen
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=N,
        r=r,
        p=p,
        dklen=dklen
    )
    
    # Ausgaben schön formatieren
    salt_hex = binascii.hexlify(salt).decode()
    key_hex = binascii.hexlify(key).decode()
    
    # Ausgabe im gleichen Format wie dein Beispiel
    scrypt_hash = f"scrypt:{N}:{r}:{p}${salt_hex}${key_hex}"
    return scrypt_hash

# Beispielnutzung
if __name__ == "__main__":
    password = "changeME0815"
    hashed = scrypt_hash_password(password)
    print("scrypt-Hash:", hashed)
