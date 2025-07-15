import socket
import uuid

from funcs import (read_port, create_folder, receive_header, print_received_header, receive_data, create_aes,
                   send_header, get_key, get_file, RECONNECT_REQUEST,
                   SUCCESSFUL_RECONNECT, SEND_AES, FAILED_REGISTRATION, REGISTRATION_REQUEST, SUCCESSFUL_REGISTRATION,
                   GENERIC_ERROR, FAILED_RECONNECT)
import threading
from structs import Client
from database import create_tables, add_client_to_db, get_data_from_db


class Server:

    def __init__(self):
        self.HOST = ''
        self.PORT = read_port()  # read the port number from "port.info"
        self.list_of_clients = []  # contain the info about the clients(objects from type Client)
        self.reconnect = True

    def serve(self):
        create_folder()  # create "received folder" if not exist
        create_tables()  # create the tables: clients and files in the database if not exist
        self.list_of_clients = get_data_from_db()  # get the current data of the clients from the database

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.HOST, self.PORT))
            sock.listen()
            print("Server listening on port number: ", self.PORT)
            while True:
                conn, addr = sock.accept()  # accept client
                threading.Thread(target=self._start_serving, args=(conn, addr)).start()

    # handle connect of client
    def _start_serving(self, conn, addr):

        lock = threading.Lock()  # to synchronize approach of many clients to the list_of_clients and the db
        try:
            with conn:
                print('Connected by', addr)
                client_id, version, code, payload_size = receive_header(conn)
                print_received_header(client_id, version, code, payload_size)
                name_bytes = receive_data(conn, payload_size)
                name = name_bytes[:name_bytes.find(b'\x00')].decode("utf-8")
                print("name of client: ", name)

                if code == RECONNECT_REQUEST:
                    print("got request to reconnect")
                    this_client = self._reconnect(lock, name, conn, client_id)
                    if this_client is not None:  # reconnect succeeded or signed as new client
                        key = this_client.key
                        if self.reconnect:  # reconnect succeeded
                            print("reconnection successful")
                            aes_key = create_aes(key, SUCCESSFUL_RECONNECT, conn, this_client.uuid)
                        else:  # signed as new client
                            print("sign as new client")
                            aes_key = create_aes(key, SEND_AES, conn, this_client.uuid)

                    else:  # this_client is none - reconnect failed and the name is already in use
                        print("can't connect with that name")
                        send_header(conn, FAILED_REGISTRATION, 0)
                        return

                elif code == REGISTRATION_REQUEST:
                    print("got request to connect")
                    flag = True
                    with lock:
                        for client in self.list_of_clients:  # check that this name is not signed already
                            if name == client.name:
                                flag = False

                    if not flag:  # this name already in use
                        print("can't connect with that name")
                        send_header(conn, FAILED_REGISTRATION, 0)
                        return

                    else:
                        print("connection successful")
                        this_client = self._create_uuid(name, lock, SUCCESSFUL_REGISTRATION, conn)
                        key = get_key(conn)  # get the public key
                        this_client.key = key
                        result = add_client_to_db(this_client, lock)  # add client details to db
                        if not result:  # error in the db - send "GENERIC_ERROR"
                            send_header(conn, GENERIC_ERROR, 0)
                        aes_key = create_aes(key, SEND_AES, conn, this_client.uuid)

                get_file(conn, aes_key, this_client, lock)

        except Exception as error:
            print("Exception: ", error)

    # handle the case of reconnect request
    def _reconnect(self, lock, name, conn, client_id):
        flag = False
        this_client = None
        with lock:
            for client in self.list_of_clients:
                if name == client.name:
                    if (client_id.hex() == str(client.uuid).replace("-", "")) and client.key is not None:
                        flag = True
                        this_client = client  # success to reconnect, get the details of that client
                        break
                    elif client_id != client.uuid:
                        flag = True
                        break  # can't reconnect and can't sign as new client because the name is already used
        if not flag:  # can't reconnect but can sign as new client
            print("can't reconnect but can sign as new client")
            this_client = self._create_uuid(name, lock, FAILED_RECONNECT, conn)
            key = get_key(conn)
            this_client.key = key
            self.reconnect = False  # to know if send "SEND_AES" or "SUCCESSFUL_RECONNECT"

        return this_client

    # create uuid number for the client and send it to him, create a Client object and insert it to the list_of_clients
    def _create_uuid(self, name, lock, code, conn):
        uuid_num = uuid.uuid4()
        print("uuid created for this client: ", str(uuid_num))
        my_client = Client(name, uuid_num)
        with lock:
            self.list_of_clients.append(my_client)
        send_header(conn, code, 0)
        conn.sendall(uuid_num.bytes)
        return my_client
