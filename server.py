#!/usr/bin/python

from cryptography.hazmat.primitives.asymmetric import ec #ellipic curves
from cryptography.hazmat.primitives.kdf.hkdf import HKDF #used for key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import os
import base64
import socket
import threading
import queue
import struct
import sys #used for command line arguments

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

def client_cleanup(client_id, conn):
    try:
        #the order of acquiring locks must be the same everywhere to avoid deadlocks
        with client_message_queues_lock:
            with active_client_ids_lock:
                if client_id in client_message_queues:
                    client_message_queues.pop(client_id)
                if client_id in active_client_ids:
                    active_client_ids.remove(client_id)
        #might be redundant, should have already close, probably ok just in case
        conn.close()
        print(f"Connection with {client_id} closed.")
        return 0
    except Exception as e:
        print(f"Error during cleanup of client {client_id}:")
        print(e)
        return 1

def sender_thread(conn : socket, client_id,  server_fernet : Fernet, client_disconnect_event : threading.Event):
    try:
        #create reference to client queue
        with client_message_queues_lock:
            if client_id  in client_message_queues:
                client_outgoing_queue = client_message_queues[client_id]
            else:
                print(f"Client {client_id} not found in client_message_queues, exiting thread.")
                client_disconnect_event.set()
                return 1
    except Exception as e:
        print("An error occured in the sender_thread:")
        print(e)
        client_disconnect_event.set()

    message = ""

    try:
        while not server_shutdown_event.is_set() and conn.fileno() != -1 and not client_disconnect_event.is_set(): #fileno returns -1 if the socket is closed
            try:
                message = client_outgoing_queue.get(timeout=0.5)
            except (TimeoutError, queue.Empty):
                #this is so the thread doesnt get stuck forever, even if server_shutdown_event is set
                continue
            if message == "exit":
                client_disconnect_event.set()
                break
            else:   
                if message == "":
                    print("Empty message, try typing something.")
                    continue
                elif message[0] == '\\':
                    token = server_fernet.encrypt(message[1:].encode()) #edge case
                else:
                    token = server_fernet.encrypt(message.encode())

                # ! - Big Endian
                # I - unsigned int
                # Converts the length of the token to a 4 byte integer (big endian)
                length_prefix = struct.pack('!I', len(token))
                # add the prefix to the token and send it
                conn.sendall(length_prefix + token)
                print(f"Message sent to {client_id}")
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print("Client disconnected (sender_thread):")
        print(e)
        client_disconnect_event.set()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt, exiting...")
        client_disconnect_event.set()
    except Exception as e:
        print("\nAn error occurred while sending messages.")
        print(e)
        client_disconnect_event.set()
        
def receiver_thread(conn : socket, client_id, server_fernet : Fernet, client_disconnect_event : threading.Event):
    try:
        while not server_shutdown_event.is_set() and conn.fileno() != -1 and not client_disconnect_event.is_set(): #fileno returns -1 if the socket is closed
            try:
                # get raw messaage length
                raw_msglen = recvall(conn, 4)
                
                if raw_msglen is None:
                    print("Connection closed by the client.")
                    client_disconnect_event.set()
                    break
                
                # get actual message length
                # !I means Unsigned int, big endian
                msglen = struct.unpack('!I', raw_msglen)[0]
                
                # get message
                token = recvall(conn, msglen)
                if token is None:
                     print("Incomplete message received. Something went wrong.")
                     client_disconnect_event.set()
                     break
                message = server_fernet.decrypt(token).decode()
                print(f"Message from {client_id}: {message}")
            except (TimeoutError, socket.timeout):
                #this is so the thread doesnt get stuck forever, even if server_shutdown_event is set
                continue
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print("Client disconnected (receiver_thread):")
                print(e)
                client_disconnect_event.set()
                break
            except KeyboardInterrupt:
                print("\nKeyboard interrupt, exiting...")
                client_disconnect_event.set()
                break
            except Exception as e:
                print("\nAn error occurred while receiving messages.")
                print(e)
                client_disconnect_event.set()
                break
        return 0
    except Exception as e:
        print(f"Unexpected error in receiver thread for client {client_id}:")
        print(e)
        client_disconnect_event.set()
        return 1

def handle_client(conn : socket, addr, client_id):
    try: 
        #ephemeral means we only use each key once
        server_private_key = ec.generate_private_key(ec.SECP384R1())
        server_public_key = server_private_key.public_key()

        with conn:
            print(f"Connected by {addr}")
            random_salt = os.urandom(16) #generate a random salt (one salt used for both handshakes, needs to be sent to the client)    
            while True:
                #2. receive client public key
                client_public_key = conn.recv(1024)
                if client_public_key:
                    #print(f"Client public key: {client_public_key}")
                    #3. send server public key
                    conn.sendall(server_public_key.public_bytes(
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        encoding=serialization.Encoding.PEM,
                    ))
                    #4. wait for acknowledgment from the client
                    ack = conn.recv(1024)
                    if not ack == b"ACK":
                        return 1 #exit if no acknowledgment

                    print(f"Received acknowledgment: {ack.decode('unicode-escape')}") #decode gets rid of the b'', allows colors in the terminal

                    #5. send random salt to the client, the salt doesnt have to be secret so this is ok!
                    print(f"generated salt: {random_salt.hex()}")
                    conn.sendall(random_salt)
                    break
                else:
                    return 1 #exit if no data is received
            
            #deserialize the received public key
            try:
                client_public_key = serialization.load_pem_public_key(client_public_key)
            except Exception as e:
                print("Failed to deserialize client public key.")
                print(e)
                return 2
            try:
                server_shared_key = server_private_key.exchange(ec.ECDH(), client_public_key) #generate shared key using ECDHE (ephemeral)
            except Exception as e:
                print("Failed to generate shared key.")
                print(e)
                return 3
            #now we derive the key using HKDF
            try:
                server_derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=random_salt,
                    info=b"HANDSHAKE_INFO", #contextual info
                ).derive(server_shared_key)
            except Exception as e:
                print("Failed to derive key.")
                print(e)
                return 4
            
            #in real life, we wouldnt print this
            print(f"Derived key: {server_derived_key.hex()}")

            #now we can send encrypted messages using the derived key
            #yippee!!

            server_fernet = Fernet(base64.urlsafe_b64encode(server_derived_key))

            client_disconnect_event = threading.Event()

            conn.settimeout(0.5) #very important!!!

            #create sender and receiver threads and start them
            new_sender_thread = threading.Thread(target=sender_thread, args=(conn, addr, server_fernet, client_disconnect_event))
            new_receiver_thread = threading.Thread(target=receiver_thread, args=(conn, addr, server_fernet, client_disconnect_event))
            with worker_threads_lock:
                worker_threads.append(new_sender_thread)
                worker_threads.append(new_receiver_thread)
                worker_threads[-2].start()
                worker_threads[-1].start()

            #wait for both threads to finish
            new_sender_thread.join()
            new_receiver_thread.join()
    except Exception as e:
        print(f"Unexpected error in handle_client for client {client_id}:")
        print(e)
    finally:
        client_cleanup(client_id, conn)
        
def print_client_ids():
    print("Here's the current list of clients:")
    #we create a copy of the list to avoid issues with threading
    with active_client_ids_lock:
        active_client_ids_copy = active_client_ids.copy() #no need for deep copy
    for i in range(0, len(active_client_ids_copy)):
        print(f"{i}. {active_client_ids_copy[i]}")
    if len(active_client_ids_copy) == 0:
        print("None")
    return active_client_ids_copy

def server_management_interface():
    try:
        while not server_shutdown_event.is_set():
            #create a copy of active_client_ids client_message_queues and  to avoid threading issues
            with client_message_queues_lock:
                client_message_queues_copy = client_message_queues.copy()
            clients_displayed = print_client_ids()
            print("Type the number of the client you would like to switch to (or 'exit' to shut down the server and sever all connections): ")
            command = input()
            if command == "exit":
                for i in client_message_queues_copy.values():
                    i.put("exit")
                server_shutdown_event.set()
                print("Server is shutting down...")
            elif command.isnumeric() and int(command) in range(0, len(clients_displayed)) and clients_displayed[int(command)] in client_message_queues_copy:
                print(f"You are now connected to client {command}")
                command = clients_displayed[int(command)] #get the actual client ID (address tuple)
                while not server_shutdown_event.is_set():
                    print("Type the message you would like to send (or 'back' to go back to the menu, 'exit' to sever the connection)")
                    message = input()
                    if message == "back":
                        break
                    elif message == "exit":
                        with client_message_queues_lock:
                            #very important if condition, we need to make sure the client queue still exists, 
                            #and the client hasnt disconnected midway communiaction
                            if command in client_message_queues:
                                client_message_queues[command].put("exit")
                            else:
                                break
                        break
                    else:
                        with client_message_queues_lock:
                            #very important if condition, we need to make sure the client queue still exists, 
                            #and the client hasnt disconnected midway communiaction
                            if command in client_message_queues:
                                client_message_queues[command].put(message)
                            else:
                                break
            else:
                print("Incorrect input, or client is already disconnected.")
                continue
    except Exception as e:
        print(e)
        server_shutdown_event.set() #hopefully the server doesnt get stuck in an infinite while true loop

def listener_thread(HOST, PORT):  
    #with makes sure the socket is closed after the block is executed
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT)) #used for the listener
        s.settimeout(0.5) #makes sure the listener thread isnt stuck listening forever
        #1. server listens for the client first
        while not server_shutdown_event.is_set():
            try:
                s.listen()
                conn, addr = s.accept()
                new_client_id = addr
                with client_message_queues_lock:
                    with active_client_ids_lock:
                        active_client_ids.append(new_client_id)
                        client_message_queues[new_client_id] = queue.Queue()
                        new_worker_thread = threading.Thread(target=handle_client, args=(conn, addr, new_client_id))
                        with worker_threads_lock:
                            worker_threads.append(new_worker_thread)
                            worker_threads[-1].start()
            except socket.timeout:
                #in the event of a timeout, simply continue listening
                #this is to ensure the thread isnt stuck listening forever, even if server_shutdown_event was set
                continue
            except OSError as e:
                if not server_shutdown_event.is_set():
                    print(f"Error in listener thread: {e}")
                server_shutdown_event.set()
                break
            except Exception as e:
                server_shutdown_event.set()
                print(f"Unexpected error in listener thread: {e}")
                break 
        return

if __name__ == "__main__":
    if len(sys.argv) == 3:
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])
    else:
        print("USAGE: server.py [HOST] [PORT]")
        print("Where HOST is the IP address the server should listen on, and PORT is the port number.")
        sys.exit(1)

    #create locks
    #global acquisition order for locks to avoid deadlocks:
    #client_message_queues_lock > active_client_ids_lock > worker_threads_lock
    client_message_queues_lock = threading.Lock()
    active_client_ids_lock = threading.Lock()
    worker_threads_lock = threading.Lock()

    #global
    worker_threads = [] #modified by listener_thread
    #server_shutdown_event must only be set if there is a critical error in the listener thread or server_management_interface
    #or if the user wants to shut down the server. Otherwise, handle all threads separately
    server_shutdown_event = threading.Event()
    client_message_queues = {}  
    active_client_ids = [] #client ID is simply the address tuple (ip, port), should be unique hopefully

    #create and start the server management interface thread
    new_management_thread = threading.Thread(target=server_management_interface, daemon=True)
    with worker_threads_lock:
        worker_threads.append(new_management_thread)
        worker_threads[0].start()

    #create and start the listener thread
    new_listener_thread = threading.Thread(target=listener_thread, args=(HOST, PORT))
    with worker_threads_lock:
        worker_threads.append(new_listener_thread)
        worker_threads[1].start()

    #wait until its time for the server to close
    try:
        server_shutdown_event.wait()
    except KeyboardInterrupt:
        print("KeyboardInterrupt detected, exiting...")
        server_shutdown_event.set()
    except Exception as e:  
        print("A critical error occured in the server script.")
        print(e)
        server_shutdown_event.set()
    finally:
        with worker_threads_lock:
            for t in worker_threads:
                #this code is so 😭
                #if a thread is reading input, it will be blocked, so it cant be joined
                # so we have to check if it's a daemon. Specifically server_management_interface is a daemon
                # server_management_interface is a daemon so it might be blocked
                if not t.daemon:
                    t.join()
    
    print("Server shutdown complete.")