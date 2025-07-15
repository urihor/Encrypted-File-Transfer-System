# Encrypted File Transfer System

## 🔐 Overview

This project implements an encrypted file transfer system using a custom client-server protocol.  
The **client** (written in C++) encrypts a file and sends it to the **server** (written in Python), which decrypts the file, saves it locally, and inserts it into a SQLite3 database.

---

## 📦 Technologies

- **Client:** C++ (C++17 or later)
- **Server:** Python 3
- **Encryption:** Crypto++ (C++), PyCryptodome (Python)
- **Database:** SQLite3
- **Libraries:** Boost (installed via NuGet for C++ client)

---

## 📁 Client File Setup

Before running the client, make sure to place the file you wish to transfer in the following location:
X64/Debug/
The file **must match the exact name** specified in the `transfer.info` file.  

