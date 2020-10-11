from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def keygen():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open('public_key.pem', 'wb') as f:
        f.write(pem)

    print("Your public key has been saved to public_key.pem.")
    print("Your private key has been saved to private_key.pem.")
    print("Type x to return to menu...")
    if input() == 'x':
        menu()
    
def menu():
    print("This program demonstrates asymmetric encryption and decryption,")
    print("as well as public and private key generation using RSA.")
    print("Please select an option")
    print("(1) Generate Keys")
    print("(2) Encrypt")
    print("(3) Decrypt")
    option = int(input(""))
    if option == 1:
        keygen()
    elif option == 2:
        print("Do you want to:")
        print("(1) Encrypt a file (.txt)")
        print("(2) Encrypt a message in the terminal")
        encrypt_option = int(input(""))
        if encrypt_option == 1:
            print("What's the name of the text file? Make sure it's in the correct directory.")
            textfile == input("")
            f = open(textfile, 'rb')
            text = f.read()
            f.close()
            encrypt(text)
        elif encrypt_option == 2:
            print("This will use the public_key.pem stored in this directory.")
            print("What message do you want to encrypt?")
            text = input("")
            text = bytes(text, 'utf-8')
            encrypt(text)
        else:
            print("Invalid option... Choose 1 or 2.")
            menu()

    elif option == 3:
        print("Which text file should be decrypted? Enter the filename.")
        file = input("")
        decrypt(file)

    else:
        print("Invalid option... Choose from 1-3.")
        menu()

def encrypt(text):
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    encrypted = public_key.encrypt(
        text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    f = open('message.encrypted', 'wb')
    f.write(encrypted)
    f.close()
    print("Press x to return to the menu.")
    if input("") == 'x':
        menu()
 
def decrypt(file):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    f = open(file, 'rb')
    encrypted = f.read()
    f.close()

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decryptedfile = file.replace('.encrypted', '.txt')

    f = open(decryptedfile, 'wb')
    f.write(decrypted)
    f.close()

    print("Your decrypted file has been saved as "+ file + ".")
    print("Press x to return to the menu.")
    if input("") == 'x':
        menu()

menu()
