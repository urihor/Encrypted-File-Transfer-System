import sqlite3
from datetime import datetime
import os
from structs import Client
import uuid


# create the tables for saving the data from the client
def create_tables():
    try:
        conn = sqlite3.connect('defensive.db')
        conn.text_factory = bytes
        # create the tables
        conn.executescript("""CREATE TABLE IF NOT EXISTS clients( 
                                ID varchar(16) NOT NULL PRIMARY KEY,
                                Name varchar(255), 
                                PublicKey varchar(160),
                                LastSeen text, 
                                AESKey varchar(32)
                            );
                            CREATE TABLE IF NOT EXISTS files(
                                ID varchar(16) NOT NULL, 
                                FileName varchar(255), 
                                PathName varchar(255),
                                Verified boolean ,
                                PRIMARY KEY(ID, FileName),
                                FOREIGN KEY (ID) REFERENCES clients(ID)
                            )""")
        # ID, FileName are primary key because a client can have more than 1 file, but can't have
        # 2 files with the same name
        conn.commit()
        conn.close()
    except Exception as error:
        print("Exception: ", error)


# get the data into list_of_clients from the db after restart the server
def get_data_from_db():
    try:
        list_of_clients = []
        conn = sqlite3.connect('defensive.db')
        conn.text_factory = bytes
        cur = conn.cursor()

        cur.execute("SELECT ID,NAME,PublicKey FROM clients")
        rows = cur.fetchall()

        for row in rows:
            client_id, name, public_key = row
            client_id2 = client_id.decode('utf-8')
            client_id_with_braces = '{' + client_id2 + '}'
            client_id_uuid = uuid.UUID(client_id_with_braces)  # make uuid object from the string
            new_client = Client(name.decode('utf-8'), client_id_uuid)  # create client object
            new_client.key = public_key  # add the public key
            cur.execute("SELECT FileName FROM files WHERE ID = ?;", (client_id.decode('utf-8'),))
            files = cur.fetchall()
            for file in files:
                new_client.files.append(file[0].decode('utf-8'))  # add all the files of this client

            list_of_clients.append(new_client)

        cur.close()
        conn.close()
        return list_of_clients
    except Exception as error:
        print("Exception: ", error)


def add_client_to_db(this_client, lock):
    try:
        with lock:
            current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            uuid_str = str(this_client.uuid)
            conn = sqlite3.connect('defensive.db')
            conn.text_factory = bytes
            conn.execute("""INSERT INTO clients(ID, Name, PublicKey, LastSeen) VALUES (?,?,?,?)""",
                         (uuid_str, this_client.name, this_client.key, current_time))
            conn.commit()
            conn.close()
            return True
    except Exception as error:
        print("Exception: ", error)
        return False


def update_clients_and_files(this_client, flag, path, aes_key, lock):
    try:
        with lock:
            current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            uuid_str = str(this_client.uuid)
            path_str = str(path)
            path_str += '\0'
            project_folder = os.getcwd()  # Get the current working directory
            full_path = os.path.join(project_folder, "received files")
            full_path = full_path + "\\" + this_client.name + ' - ' + path_str
            conn = sqlite3.connect('defensive.db')
            conn.text_factory = bytes
            conn.execute("""UPDATE clients SET LastSeen = ?, AESKey = ? WHERE ID = ?""", (current_time, aes_key,
                                                                                          uuid_str))
            conn.execute("""INSERT OR REPLACE INTO files(ID, FileName, PathName, Verified) VALUES (?,?,?,?)""",
                         (uuid_str, path_str, full_path, flag))
            conn.commit()
            conn.close()
            return True
    except Exception as error:
        print("Exception: ", error)
        return False
