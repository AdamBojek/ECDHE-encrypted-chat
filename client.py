#! C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0\python3.11.exe

from cryptography.hazmat.primitives.asymmetric import ec #ellipic curves
from cryptography.hazmat.primitives.kdf.hkdf import HKDF #used for key derivation   
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken # import InvalidToken for exception handling
from cryptography.hazmat.primitives import serialization
import socket
import base64
import sys
import threading

def receiver_thread(s : socket, client_fernet : Fernet, disconnect_event : threading.Event):
    while not disconnect_event.is_set():
        try:
            token = s.recv(1024)
            if not token: #or token == b""
                print("Connection closed by the server.")
                disconnect_event.set()
                break
        except socket.timeout:
            continue
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            disconnect_event.set()
            break
        try:
            print(client_fernet.decrypt(token).decode()) #allows colors in the terminal
        except InvalidToken as e:
            print("Invalid token received, maybe the keys dont match?")
            print(e)
            disconnect_event.set()
            break
        except Exception as e:
            print("An error occurred during decryption:")
            print(e)
            disconnect_event.set()
            break

def sender_thread(s : socket, client_fernet : Fernet, disconnect_event : threading.Event):
    while not disconnect_event.is_set():
        try:
            print("Enter message (or 'exit' to quit): ")
            message = input()
            if message == "exit":
                disconnect_event.set()
                break
            else:
                if message == "":
                    if disconnect_event.is_set():
                        break
                    else:
                        print("Empty message, try typing something.")
                        continue
                elif message[0] == '\\':
                    token = client_fernet.encrypt(message[1:].encode()) #edge case
                else:
                    token = client_fernet.encrypt(message.encode())
                s.sendall(token)
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected, exiting...")
            disconnect_event.set()
            break
        except Exception as e:
            disconnect_event.set()
            print("An error occurred during encryption or sending:")
            print(e)
            break

if __name__ == "__main__":
    if len(sys.argv) == 3:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    else:
        #set to default values
        HOST = "127.0.0.1"
        PORT = 65432

    client_private_key = ec.generate_private_key(ec.SECP384R1())
    client_public_key = client_private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #1. connect to the server and send client public key
        try:
            s.connect((HOST, PORT)) #used for the client
        except Exception as e:
            print("Failed to connect to the server.")
            print(e)
            exit(1)
        print("Client IP address: ", s.getsockname()) #get CLIENT ip addr
        s.sendall(client_public_key.public_bytes(
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encoding=serialization.Encoding.PEM,
        ))

        #2. receive server public key
        server_public_key = s.recv(1024)

        #3. send acknowledgment to the server
        s.sendall(b"ACK")

        #4. receive random salt from the server
        random_salt = s.recv(1024)

        #deserialize the received public key
        try:
            server_public_key = serialization.load_pem_public_key(server_public_key)
        except Exception as e:
            print("Failed to deserialize server public key.")
            print(e)
            exit(2)
        client_shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

        try:
            client_derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=random_salt,
                info=b"HANDSHAKE_INFO", #contextual info, needs to be the same for both handshakes
            ).derive(client_shared_key)
        except Exception as e:
            print("Failed to derive key.")
            print(e)
            exit(3)

        print(f"Derived key: {client_derived_key.hex()}")

        #now we can send encrypted messages using the derived key
        #yippee!!

        client_fernet = Fernet(base64.urlsafe_b64encode(client_derived_key))

        worker_threads = []
        disconnect_event = threading.Event()

        s.settimeout(0.5)

        new_sender_thread = threading.Thread(target=sender_thread, args=(s, client_fernet, disconnect_event))
        new_receiver_thread = threading.Thread(target=receiver_thread, args=(s, client_fernet, disconnect_event))
        worker_threads.append(new_receiver_thread)
        worker_threads.append(new_sender_thread)

        for t in worker_threads:
            t.start()

        #wait until its time for the client to close
        try:
            disconnect_event.wait()
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected, exiting...")
            disconnect_event.set()
        except Exception as e:
            print("An error occured while joining the threads.")
            print(e)
            disconnect_event.set()
        finally:
            for t in worker_threads:
                t.join()

        print("Disconnected from the server.")

    