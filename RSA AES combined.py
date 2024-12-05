import os
import ctypes
from cryptography.hazmat.primitives import hashes, padding, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import sys


# Функція для безпечного очищення пам'яті
def clear_sensitive_data(data: object):
    if isinstance(data, bytes):
        ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(data)), 0, len(data))
    elif isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, memoryview):
        data[:] = b'\x00' * len(data)

# Клас для роботи з AES (Advanced Encryption Standard)
class AESFileCipher:
    def __init__(self, password: str):
        # Зберігаю пароль, генерую випадкові salt і IV (ініціалізаційний вектор)
        self.password = password.encode()  # Пароль у байтах
        self.salt = os.urandom(16)  # Salt для KDF
        self.iv = os.urandom(16)  # IV (Initialization Vector) для шифрування AES
        self.key = self._generate_key()  # Генеруємо AES ключ

    # Генерація AES-ключа на основі пароля та salt
    def _generate_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Хеш-функція для KDF
            length=32,  # Довжина ключа AES (256 біт)
            salt=self.salt,
            iterations=100000,  # Кількість ітерацій для посилення захисту
        )
        return kdf.derive(self.password)  # Генеруємо ключ

    # Шифрування файлу
    def encrypt_file(self, input_file: str, output_file: str):
        try:
            with open(input_file, "rb") as f:
                data = f.read()  # Зчитуємо вміст файлу

            # Додаємо доповнення (padding) до даних для відповідності блоку AES
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            # Створюємо AES шифратор у режимі CBC
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Генеруємо HMAC для перевірки цілісності даних
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(encrypted_data)
            mac = h.finalize()

            # Зберігаємо salt, IV, MAC і зашифровані дані у вихідний файл
            with open(output_file, "wb") as f:
                f.write(self.salt + self.iv + mac + encrypted_data)

            print(f"Файл '{input_file}' зашифровано і збережено як '{output_file}'.")

        finally:
            # Очищуємо пам'ять від ключів
            clear_sensitive_data(self.key)
            clear_sensitive_data(self.password)

    # Дешифрування файлу
    def decrypt_file(self, encrypted_file: str, output_file: str):
        try:
            with open(encrypted_file, "rb") as f:
                content = f.read()  # Зчитуємо вміст зашифрованого файлу

            # Розділяємо вміст файлу на salt, IV, MAC та зашифровані дані
            salt, iv, mac, encrypted_data = content[:16], content[16:32], content[32:64], content[64:]

            # Відновлюємо AES-ключ із пароля та salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(self.password)

            # Перевіряємо MAC для валідації даних
            h = hmac.HMAC(key, hashes.SHA256())
            h.update(encrypted_data)
            try:
                h.verify(mac)  # Якщо MAC не співпадає, буде виключення
                print("MAC успішно перевірено.")
            except Exception:
                print("Помилка MAC! Дані можуть бути змінені.")
                return

            # Дешифруємо дані за допомогою AES у режимі CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Знімаємо доповнення (padding)
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

            # Зберігаємо дешифровані дані у вихідний файл
            with open(output_file, "wb") as f:
                f.write(data)

            print(f"Файл '{encrypted_file}' дешифровано і збережено як '{output_file}'.")

        finally:
            # Очищуємо пам'ять від ключів
            clear_sensitive_data(self.key)
            clear_sensitive_data(self.password)

# Клас для роботи з RSA (Rivest–Shamir–Adleman)
class RSAFileCipher:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    # Генерація RSA ключів (приватний та публічний)
    def generate_keys(self, private_key_file: str, public_key_file: str):
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,  # Загальне значення для RSA
                key_size=2048,  # Розмір ключа (2048 біт)
            )
            self.public_key = self.private_key.public_key()  # Витягуємо публічний ключ

            # Зберігаємо приватний ключ у файл
            with open(private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,  # Формат PEM
                    format=serialization.PrivateFormat.PKCS8,  # Формат PKCS8
                    encryption_algorithm=serialization.NoEncryption()  # Без шифрування
                ))

            # Зберігаємо публічний ключ у файл
            with open(public_key_file, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            print(f"Ключі збережено у файли: {private_key_file} та {public_key_file}")
        finally:
            # Очищуємо пам'ять від ключів
            clear_sensitive_data(self.private_key)
            clear_sensitive_data(self.public_key)

    # Шифрування файлу за допомогою RSA
    def encrypt_file(self, input_file: str, output_file: str, public_key_file: str):
        try:
            with open(public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())  # Завантажуємо публічний ключ

            with open(input_file, "rb") as f:
                data = f.read()  # Читаємо вхідний файл

            # Шифруємо дані за допомогою RSA-OAEP
            encrypted_data = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # Захист через MGF1
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Зберігаємо зашифровані дані у файл
            with open(output_file, "wb") as f:
                f.write(encrypted_data)

            print(f"Файл '{input_file}' зашифровано і збережено як '{output_file}'.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(encrypted_data)
            clear_sensitive_data(self.public_key)
            clear_sensitive_data(self.private_key)

    # Метод для підписання файлу за допомогою RSA приватного ключа
    def sign_file(self, input_file: str, signature_file: str, private_key_file: str):
        try:
            # Завантажуємо приватний ключ із вказаного файлу
            with open(private_key_file, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Зчитуємо вхідний файл, який потрібно підписати
            with open(input_file, "rb") as f:
                data = f.read()

            # Генеруємо цифровий підпис для даних
            signature = private_key.sign(
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),  # Захист через MGF1
                    salt_length=asym_padding.PSS.MAX_LENGTH  # Максимальна довжина salt
                ),
                hashes.SHA256()  # Хешування даних перед підписанням
            )

            # Зберігаємо підпис у файл
            with open(signature_file, "wb") as f:
                f.write(signature)

            print(f"Файл підписано. Підпис збережено у '{signature_file}'.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(signature)
            clear_sensitive_data(self.private_key)

    # Метод для перевірки цифрового підпису файлу за допомогою RSA публічного ключа
    def verify_signature(self, input_file: str, signature_file: str, public_key_file: str):
        try:
            # Завантажуємо публічний ключ із вказаного файлу
            with open(public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Зчитуємо вхідний файл, підпис якого потрібно перевірити
            with open(input_file, "rb") as f:
                data = f.read()

            # Зчитуємо цифровий підпис із відповідного файлу
            with open(signature_file, "rb") as f:
                signature = f.read()

            # Перевіряємо підпис
            public_key.verify(
                signature,  # Цифровий підпис
                data,  # Оригінальні дані
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),  # Захист через MGF1
                    salt_length=asym_padding.PSS.MAX_LENGTH  # Максимальна довжина salt
                ),
                hashes.SHA256()  # Хешування даних перед перевіркою
            )
            print("Підпис успішно перевірено.")
        except Exception:
            print("Помилка перевірки підпису! Дані можуть бути змінені.")
        finally:
            # Очищуємо пам'ять від чутливих даних
            clear_sensitive_data(data)
            clear_sensitive_data(signature)

def hidden_password_readline():
    password = '*'
    print("Введіть пароль: ", end='', flush=True)
    while True:
        char = sys.stdin.read(1)  # Читання одного символу
        if char == '\n':  # Enter
            break
        elif char == '\b':  # Backspace
            if password:
                password = password[:-1]
                print("\b \b", end='', flush=True)
        else:
            password += char
            print("*", end='', flush=True)
    print()
    return password


def aes_interface():
    while True:
        print("\n====== AES Інтерфейс ======")
        print("1. Шифрування файлу")
        print("2. Дешифрування файлу")
        print("3. Вихід до головного меню")

        choice = input("Ваш вибір: ")

        if choice == "1":
            input_file = input("Введіть шлях до вхідного файлу: ")
            output_file = input("Введіть шлях для збереження зашифрованого файлу: ")
            password = hidden_password_readline()
            aes_cipher = AESFileCipher(password=password)
            aes_cipher.encrypt_file(input_file, output_file)
        elif choice == "2":
            encrypted_file = input("Введіть шлях до зашифрованого файлу: ")
            output_file = input("Введіть шлях для збереження дешифрованого файлу: ")
            password = hidden_password_readline()
            aes_cipher = AESFileCipher(password=password)
            aes_cipher.decrypt_file(encrypted_file, output_file)
        elif choice == "3":
            print("Повернення до головного меню.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")


def rsa_interface():
    rsa_cipher = RSAFileCipher()

    while True:
        print("\n====== RSA Інтерфейс ======")
        print("1. Генерація RSA ключів")
        print("2. Шифрування файлу (RSA)")
        print("3. Дешифрування файлу (RSA)")
        print("4. Підписання файлу (RSA)")
        print("5. Перевірка підпису (RSA)")
        print("6. Вихід до головного меню")

        choice = input("Ваш вибір: ")

        if choice == "1":
            private_key_file = input("Введіть шлях для збереження приватного ключа: ")
            public_key_file = input("Введіть шлях для збереження публічного ключа: ")
            rsa_cipher.generate_keys(private_key_file, public_key_file)
        elif choice == "2":
            input_file = input("Введіть шлях до вхідного файлу: ")
            output_file = input("Введіть шлях для збереження зашифрованого файлу: ")
            public_key_file = input("Введіть шлях до публічного ключа: ")
            rsa_cipher.encrypt_file(input_file, output_file, public_key_file)
        elif choice == "3":
            encrypted_file = input("Введіть шлях до зашифрованого файлу: ")
            output_file = input("Введіть шлях для збереження дешифрованого файлу: ")
            private_key_file = input("Введіть шлях до приватного ключа: ")
            rsa_cipher.decrypt_file(encrypted_file, output_file, private_key_file)
        elif choice == "4":
            input_file = input("Введіть шлях до вхідного файлу: ")
            signature_file = input("Введіть шлях для збереження підпису: ")
            private_key_file = input("Введіть шлях до приватного ключа: ")
            rsa_cipher.sign_file(input_file, signature_file, private_key_file)
        elif choice == "5":
            input_file = input("Введіть шлях до вхідного файлу: ")
            signature_file = input("Введіть шлях до файлу з підписом: ")
            public_key_file = input("Введіть шлях до публічного ключа: ")
            rsa_cipher.verify_signature(input_file, signature_file, public_key_file)
        elif choice == "6":
            print("Повернення до головного меню.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")


def main():
    while True:
        print("\n====== Головне меню ======")
        print("1. AES Інтерфейс")
        print("2. RSA Інтерфейс")
        print("3. Вихід")

        choice = input("Ваш вибір: ")

        if choice == "1":
            aes_interface()
        elif choice == "2":
            rsa_interface()
        elif choice == "3":
            print("Завершення програми.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")


if __name__ == "__main__":
    main()