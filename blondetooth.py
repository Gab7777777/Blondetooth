print("\033[91m+++BLONDETOOTH+++\033[0m")
print("\033[96mV 1.0 Poison Corp. 2024\033[0m")
print("Librerías requeridas:")
print("# - pycryptodome: Para el cifrado")
print("# - hashlib: Para cálculos hash")

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Función de encriptación (ECB)
def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data))
    return encrypted_data

# Función de desencriptado (ECB)
def decrypt_ecb(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

# Función para completar los datos con padding
def pad(data):
    length = len(data)
    padding_amount = AES.block_size - (length % AES.block_size)
    return data + bytes([padding_amount] * padding_amount)

# Función para eliminar el padding después de desencriptar
def unpad(data):
    padding_amount = data[-1]
    return data[:-padding_amount]

# Función principal del programa
def main():
    opcion = input("Ingrese 1 para encriptar o 2 para desencriptar: ")

    if opcion == '1':
        # Opción para encriptar
        texto = input("Ingrese el texto que desea encriptar: ")
        clave = input("Ingrese la clave (16, 24 o 32 caracteres): ")

        # Validar la longitud de la clave
        if len(clave) not in [16, 24, 32]:
            print("La clave debe tener 16, 24 o 32 caracteres.")
            return

        # Convertir el texto y la clave a bytes
        texto_bytes = texto.encode()
        clave_bytes = clave.encode()

        # Encriptar el texto
        texto_encriptado = encrypt_ecb(texto_bytes, clave_bytes)
        print("Texto encriptado:", texto_encriptado.hex())

    elif opcion == '2':
        # Opción para desencriptar
        texto_encriptado_hex = input("Ingrese el texto encriptado en formato hexadecimal: ")
        clave = input("Ingrese la clave (16, 24 o 32 caracteres): ")

        # Validar la longitud de la clave
        if len(clave) not in [16, 24, 32]:
            print("La clave debe tener 16, 24 o 32 caracteres.")
            return

        # Convertir el texto encriptado y la clave a bytes
        texto_encriptado = bytes.fromhex(texto_encriptado_hex)
        clave_bytes = clave.encode()

        # Desencriptar el texto
        try:
            texto_desencriptado = decrypt_ecb(texto_encriptado, clave_bytes)
            print("Texto desencriptado:", texto_desencriptado.decode())
        except ValueError:
            print("El texto encriptado o la clave son incorrectos.")

    else:
        print("Opción no válida. Debe ingresar 1 o 2.")

# Ejecutar la función principal
if __name__ == "__main__":
    main()
