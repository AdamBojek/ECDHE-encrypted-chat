#!/usr/bin/python

from cryptography.hazmat.primitives.asymmetric import ec #ellipic curves
from cryptography.hazmat.primitives.kdf.hkdf import HKDF #used for key derivation   
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken # import InvalidToken for exception handling
from cryptography.hazmat.primitives import serialization
import socket
import base64
import sys
import threading
import struct

def recvall(sock, n):
    # helper function to receive EXACTLY n bytes. recv() is not guaranteed to return exactly n bytes.abs
    # Returns None if EOF is hit
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except socket.timeout:
            #pass the exception to the caller
            raise 
    return data

def receiver_thread(s : socket, client_fernet : Fernet, disconnect_event : threading.Event):
    while not disconnect_event.is_set():
        try:
            # get the raw message length (bytes)
            raw_msglen = recvall(s, 4)
            
            if raw_msglen is None:
                print("Connection closed by the server.")
                disconnect_event.set()
                break
            
            # get the actual message length
            # !I means Unsigned int, big endian
            msglen = struct.unpack('!I', raw_msglen)[0]

            # get the message
            token = recvall(s, msglen)
            if token is None:
                print("Connection closed during message body reception.")
                disconnect_event.set()
                break
        except socket.timeout:
            continue
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            disconnect_event.set()
            break
        try:
            print(client_fernet.decrypt(token).decode()) 
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
                
                # ! - Big Endian
                # I - unsigned int
                # Converts the length of the token to a 4 byte integer (big endian)
                length_prefix = struct.pack('!I', len(token))
                # add the prefix to the token and send it
                s.sendall(length_prefix + token)
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
        print("USAGE: client.py [HOST] [PORT]")
        print("Where HOST is the IP address of the server and PORT is the port number.")
        sys.exit(1)

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

        new_sender_thread = threading.Thread(target=sender_thread, daemon=True,args=(s, client_fernet, disconnect_event))
        new_receiver_thread = threading.Thread(target=receiver_thread, daemon=True, args=(s, client_fernet, disconnect_event))
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
            try:
                s.close() 
            except:
                pass
            
            #the threads are daemons so we dont need to join them manually
            pass
            

        print("Disconnected from the server.")

    