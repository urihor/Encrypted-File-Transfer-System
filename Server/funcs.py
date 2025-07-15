import os
from structs import Header
import struct
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import cksum
from database import update_clients_and_files

REGISTRATION_REQUEST = 1025
RECONNECT_REQUEST = 1027
CORRECT_CRC = 1029
FAILED_AND_FINISH = 1031
SUCCESSFUL_REGISTRATION = 1600
FAILED_REGISTRATION = 1601
SEND_AES = 1602
SEND_CRC = 1603
ACCEPT_MESSAGE = 1604
SUCCESSFUL_RECONNECT = 1605
FAILED_RECONNECT = 1606
GENERIC_ERROR = 1607
SIZE_OF_PACKET = 279
SIZE_OF_AES = 32
DEFAULT_PORT = 1256
FIXED_SIZE_IN_PACKET = 267
RECONNECT_FLAG = True
SIZE_OF_UUID = 16
SIZE_OF_NAME = 255
SIZE_OF_PUBLIC_KEY = 160
SIZE_OF_FILE_NAME = 255


# read the port number from the file "port.info"
def read_port():
    try:
        f = open("port.info", "r")
        port = f.readline()
        # check that tne port number is valid
        if not port.isdigit():  # the port contains non digits
            return DEFAULT_PORT
        if int(port) < 0 or int(port) > 65535:  # number of port is illegal
            return DEFAULT_PORT
        return int(port)
    except Exception as error:
        print("Exception: ", error)
        return DEFAULT_PORT


# receive data from the socket
def receive_data(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Socket connection broken")
        data += chunk
    return data


# create the folder "received files" if not exist
def create_folder():
    try:
        if not os.path.exists("received files"):
            os.makedirs("received files")
    except OSError as error:
        print("Can't create folder:", error)


# got a header from the client
def receive_header(conn):
    header_format = f'<{SIZE_OF_UUID}sBHI'
    header_size = struct.calcsize(header_format)
    serialized_header = receive_data(conn, header_size)
    unpacked_data = struct.unpack(header_format, serialized_header)  # # Unpack the binary data using the header format
    return unpacked_data


def print_received_header(client_id, version, code, payload_size):
    print("Received header: ")
    print("    Client ID: ", client_id.hex())
    print("    Version: ", version)
    print("    Code:", code)
    print("    Payload Size: ", payload_size)


def print_send_header(header):
    print("Sent header: ")
    print("    Version: ", header.version)
    print("    Code: ", header.code)
    print("    Payload Size: ", header.payload_size)


# encrypt the aes key by the public key
def create_key(key, aes_key):
    rsa_key = RSA.import_key(key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key


# decrypt the text was sent by the aes key, create a file from this text and calculate its checksum
def create_file(conn, name, whole_message, aes_key, my_client):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
    decrypted_text = unpad(cipher.decrypt(whole_message), AES.block_size)
    # define the folder and file paths
    project_folder = os.getcwd()  # get the current working directory
    received_files_folder = os.path.join(project_folder, "received files")
    file_name = f"{my_client.name} - {name.decode('utf-8')}"
    file_path = os.path.join(received_files_folder, file_name)

    try:
        with open(file_path, 'wb') as file:
            file.write(decrypted_text)

        print("File", file_name, " created successfully.")
        checksum = cksum.readfile(file_path)
        return checksum
    except Exception as error:
        print("Exception: ", error)
        send_header(conn, GENERIC_ERROR, 0)  # can't create the file


# create a header and send it
def send_header(conn, code, size):
    h = Header(code, size)
    header_data = struct.pack('<BHI', h.version, h.code, h.payload_size)
    conn.sendall(header_data)
    print_send_header(h)


# create aes key , send it to "create_key" to encrypt it, and then send the encrypted key to the client
def create_aes(key, code, conn, uuid_num):
    aes_key = get_random_bytes(SIZE_OF_AES)
    encrypted_aes_key = create_key(key, aes_key)
    print("got public key, sending aes key to the client")
    send_header(conn, code, len(uuid_num.bytes) + len(encrypted_aes_key))
    conn.sendall(uuid_num.bytes + encrypted_aes_key)
    return aes_key


# get the public key from the client
def get_key(conn):
    client_id, version, code, payload_size = receive_header(conn)
    # display the received data
    print_received_header(client_id, version, code, payload_size)
    contents_data = receive_data(conn, payload_size)
    format_string = f'<{SIZE_OF_NAME}s{SIZE_OF_PUBLIC_KEY}s'
    name, key = struct.unpack(format_string, contents_data)
    return key


# print the contents of a packet and return the name of the file was sent
def print_packet(current, total, path):
    null_byte_index = path.find(b'\x00')
    path = path[:null_byte_index]
    print("current packet is number: ", current)
    print("total number of packets is: ", total)
    print("name of file is: ", path.decode('utf-8'))
    return path


# send an answer message after got the file
def send_packet(conn, checksum, client_id, whole_message, path):
    print("checksum is: ", checksum)
    checksum_value = checksum.split()
    send_header(conn, SEND_CRC, SIZE_OF_PACKET)
    uuid_num = struct.pack(f'<{SIZE_OF_UUID}s', client_id)
    size = struct.pack('<I', len(whole_message))  # the size of the file after encrypted
    file_name = struct.pack(f'<{SIZE_OF_FILE_NAME}s', path)
    cksum_value = struct.pack('<I', int(checksum_value[0]))

    # concatenate the parts to create the final message
    message = uuid_num + size + file_name + cksum_value
    conn.sendall(message)


# get from client if the CRC is correct
def get_answer(conn, my_client, path, aes_key, lock):
    client_id, version, code, payload_size = receive_header(conn)
    print_received_header(client_id, version, code, payload_size)
    name_file = receive_data(conn, payload_size)
    print("name of file was sent: ", name_file[:name_file.find(b'\x00')].decode('utf-8'))

    if code == CORRECT_CRC or code == FAILED_AND_FINISH:
        send_header(conn, ACCEPT_MESSAGE, len(my_client.uuid.bytes))
        conn.sendall(my_client.uuid.bytes)
        print("finished with this client")
        if code == CORRECT_CRC:
            print("file sent successfully")
            my_client.files.append(path)  # add this file to the list of files this client sent
            result = update_clients_and_files(my_client, True, path, aes_key, lock)  # update the db

        else:
            print("failed to get the file")
            result = update_clients_and_files(my_client, False, path, aes_key, lock)  # # update the db
        print("---------------------------------------------------------------")
        if not result:  # error in the db - send "GENERIC_ERROR"
            send_header(conn, GENERIC_ERROR, 0)
    return code


# get the contents of the encrypted file from client
def get_file(conn, aes_key, my_client, lock):
    print("start getting the file")
    while True:  # for case that the crc is wrong and the client send more than one time
        whole_message = b''
        while True:  # get the contents of the file
            client_id, version, code, payload_size = receive_header(conn)
            print_received_header(client_id, version, code, payload_size)
            format_string = f'<IIHH{SIZE_OF_FILE_NAME}s{payload_size - FIXED_SIZE_IN_PACKET}s'
            received_data = receive_data(conn, payload_size)
            afterSize, beforeSize, current, total, path, message = struct.unpack(format_string, received_data)
            path = print_packet(current, total, path)

            if current == total:  # in the last message not all the packet will contain part of the file
                if afterSize % (payload_size-FIXED_SIZE_IN_PACKET) != 0:
                    message = message[:(afterSize % (payload_size-FIXED_SIZE_IN_PACKET))]
                whole_message += message
                break

            whole_message += message

        checksum = create_file(conn, path, whole_message, aes_key, my_client)  # calculate the checksum
        send_packet(conn, checksum, client_id, whole_message, path)
        code = get_answer(conn, my_client, path, aes_key, lock)
        if code == CORRECT_CRC or code == FAILED_AND_FINISH:
            break  # the client will not send again
        print("try to get the file another time")
