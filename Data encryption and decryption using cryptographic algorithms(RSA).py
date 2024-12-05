"""Асиметричне шифрування та цифровий підпис за допомогою алгоритму RSA (додаткове завдання для поглибленого вивчення):

    Генерація пари ключів RSA (приватного та публічного).
    Реалізація шифрування файлу за допомогою публічного ключа та дешифрування за допомогою приватного.
    Створення цифрового підпису файлу з використанням приватного ключа та перевірка підпису за допомогою публічного ключа."""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# Генерація пари ключів
def generate_rsa_keys(private_key_file: str, public_key_file: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Збереження приватного ключа
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Збереження публічного ключа
    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Ключі збережено у файли: {private_key_file} та {public_key_file}")

# Шифрування файлу за допомогою публічного ключа
def encrypt_file_rsa(input_file: str, output_file: str, public_key_file: str):
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Зчитування даних
    with open(input_file, "rb") as f:
        data = f.read()

    # Шифрування
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Збереження шифрованих даних
    with open(output_file, "wb") as f:
        f.write(encrypted_data)

    print(f"Файл '{input_file}' зашифровано і збережено як '{output_file}'.")

# Дешифрування файлу за допомогою приватного ключа
def decrypt_file_rsa(encrypted_file: str, output_file: str, private_key_file: str):
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Зчитування зашифрованих даних
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()

    # Дешифрування
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Збереження дешифрованих даних
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"Файл '{encrypted_file}' дешифровано і збережено як '{output_file}'.")

# Підписання файлу
def sign_file(input_file: str, signature_file: str, private_key_file: str):
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Зчитування даних
    with open(input_file, "rb") as f:
        data = f.read()

    # Створення цифрового підпису
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Збереження підпису
    with open(signature_file, "wb") as f:
        f.write(signature)

    print(f"Файл підписано. Підпис збережено у '{signature_file}'.")

# Перевірка підпису
def verify_signature(input_file: str, signature_file: str, public_key_file: str):
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Зчитування даних
    with open(input_file, "rb") as f:
        data = f.read()

    # Зчитування підпису
    with open(signature_file, "rb") as f:
        signature = f.read()

    # Перевірка підпису
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Підпис успішно перевірено. Дані автентичні.")
    except Exception as e:
        print("Помилка перевірки підпису! Дані можуть бути змінені.")

# Демонстрація роботи
def main():
    while True:
        print("\nВиберіть операцію:")
        print("1. Генерація RSA ключів")
        print("2. Шифрування файлу (RSA)")
        print("3. Дешифрування файлу (RSA)")
        print("4. Підписання файлу (RSA)")
        print("5. Перевірка підпису (RSA)")
        print("6. Вихід")

        choice = input("Ваш вибір: ")

        if choice == "1":
            private_key_file = input("Введіть шлях для збереження приватного ключа: ")
            public_key_file = input("Введіть шлях для збереження публічного ключа: ")
            generate_rsa_keys(private_key_file, public_key_file)
        elif choice == "2":
            input_file = input("Введіть шлях до вхідного файлу: ")
            output_file = input("Введіть шлях для збереження зашифрованого файлу: ")
            public_key_file = input("Введіть шлях до публічного ключа: ")
            encrypt_file_rsa(input_file, output_file, public_key_file)
        elif choice == "3":
            encrypted_file = input("Введіть шлях до зашифрованого файлу: ")
            output_file = input("Введіть шлях для збереження дешифрованого файлу: ")
            private_key_file = input("Введіть шлях до приватного ключа: ")
            decrypt_file_rsa(encrypted_file, output_file, private_key_file)
        elif choice == "4":
            input_file = input("Введіть шлях до вхідного файлу: ")
            signature_file = input("Введіть шлях для збереження підпису: ")
            private_key_file = input("Введіть шлях до приватного ключа: ")
            sign_file(input_file, signature_file, private_key_file)
        elif choice == "5":
            input_file = input("Введіть шлях до вхідного файлу: ")
            signature_file = input("Введіть шлях до файлу з підписом: ")
            public_key_file = input("Введіть шлях до публічного ключа: ")
            verify_signature(input_file, signature_file, public_key_file)
        elif choice == "6":
            print("Завершення програми.")
            break  # Вихід з циклу та завершення програми
        else:
            print("Невірний вибір. Спробуйте ще раз.")

if __name__ == "__main__":
    main()
