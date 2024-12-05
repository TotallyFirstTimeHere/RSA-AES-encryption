"""Симетричне шифрування та дешифрування файлів за допомогою алгоритму AES у режимі CBC:

    Генерація криптографічного ключа та вектора ініціалізації (IV) з використанням безпечних методів.
    Реалізація шифрування вхідного файлу та збереження шифрованих даних у вихідний файл.
    Додавання MAC (Message Authentication Code) для забезпечення цілісності та автентичності даних."""

import os
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Генерація ключа AES
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-бітний ключ
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Функція шифрування файлу
def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password.encode(), salt)

    # Зчитування даних
    with open(input_file, "rb") as f:
        data = f.read()

    # Доповнення даних
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Шифрування
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Генерація MAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()

    # Запис результатів у файл
    with open(output_file, "wb") as f:
        f.write(salt + iv + mac + encrypted_data)

    print(f"Файл '{input_file}' зашифровано і збережено як '{output_file}'.")

# Функція дешифрування файлу
def decrypt_file(encrypted_file: str, output_file: str, password: str):
    with open(encrypted_file, "rb") as f:
        content = f.read()

    # Витяг параметрів
    salt, iv, mac, encrypted_data = content[:16], content[16:32], content[32:64], content[64:]
    key = generate_key(password.encode(), salt)

    # Перевірка MAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(mac)
        print("MAC успішно перевірено.")
    except Exception as e:
        print("Помилка MAC! Дані могли бути змінені.")
        return

    # Дешифрування
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Видалення доповнення
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Запис результатів у файл
    with open(output_file, "wb") as f:
        f.write(data)

    print(f"Файл '{encrypted_file}' дешифровано і збережено як '{output_file}'.")

# Демонстрація роботи програми
def main():
    while True:
        print("\nВиберіть операцію:")
        print("1. Шифрування файлу")
        print("2. Дешифрування файлу")
        print("3. Вихід")

        choice = input("Ваш вибір: ")

        if choice == "1":
            input_file = input("Введіть шлях до вхідного файлу: ")
            output_file = input("Введіть шлях для збереження зашифрованого файлу: ")
            password = input("Введіть пароль: ")
            encrypt_file(input_file, output_file, password)
        elif choice == "2":
            encrypted_file = input("Введіть шлях до зашифрованого файлу: ")
            output_file = input("Введіть шлях для збереження дешифрованого файлу: ")
            password = input("Введіть пароль: ")
            decrypt_file(encrypted_file, output_file, password)
        elif choice == "3":
            print("Завершення програми.")
            break  # Вихід з циклу та завершення програми
        else:
            print("Невірний вибір. Спробуйте ще раз.")

if __name__ == "__main__":
    main()
