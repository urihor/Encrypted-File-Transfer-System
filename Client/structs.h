#pragma once
#include <cstdint>
#include <string>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <array>
#include <vector>
#include <string>

static const int UUID_SIZE = 16;
static const uint8_t VERSION = 3;
static const uint32_t SIZE_OF_PUB_KEY = 160;
static const uint32_t MAX_FILE_NAME = 255;
static const uint32_t MAX_NAME = 255;
static const uint32_t CHANGING_SIZE_IN_PACKET = 65269;


/* header that the client send to the server*/
#pragma pack(push, 1)
class SendHeader {
	private:

		std::array<uint8_t, UUID_SIZE> idArray{};
		std::uint8_t version;
		std::uint16_t code;
		std::uint32_t payloadSize;

	public:
		SendHeader(const std::array<uint8_t, UUID_SIZE>& idArray, const uint16_t code, const uint32_t size);
		~SendHeader();
		std::string getId() const;
		std::uint16_t getCode() const;
		std::uint32_t getPayloadSize() const;
};
#pragma pack(pop)


/*header that the client get from the server*/
#pragma pack(push, 1)
class RecievedHeader {
	private:

		std::uint8_t version;
		std::uint16_t code;
		std::uint32_t payloadSize;

	public:

		RecievedHeader();
		RecievedHeader(const uint8_t version, const uint16_t code, const uint32_t size);
		~RecievedHeader();
		std::uint8_t getVersion() const;
		std::uint16_t getCode() const;
		std::uint32_t getPayloadSize() const;

};
#pragma pack(pop)


/*packet that the client send to the server with part of the encrypt file*/
#pragma pack(push, 1)
class FilePacket {
	private:

		std::uint32_t afterSize;;
		std::uint32_t beforeSize;
		std::uint16_t current;
		std::uint16_t total;
		std::array<char, MAX_FILE_NAME>path{};
		std::array<char, CHANGING_SIZE_IN_PACKET>message{};

	public:
		FilePacket(const uint32_t afterSize, const uint32_t beforeSize, const uint16_t current, const uint16_t total, const std::string& path, const std::string& message);
		~FilePacket();
};
#pragma pack(pop)


/*packet that the client send to the server with the public key */
#pragma pack(push, 1)
class KeyPacket {
	private:
		std::array<char, MAX_NAME>name{};
		std::array<char, SIZE_OF_PUB_KEY>key{};

	public:
		KeyPacket(const std::string& name, const std::string& key);
		~KeyPacket();
};
#pragma pack(pop)


/* an answer message to the client after the server got the file*/
#pragma pack(push, 1)
class CRCMessage {
	private:
			std::array<uint8_t, UUID_SIZE> idArray;
			std::uint32_t size;
			std::array<char, MAX_FILE_NAME>fileName;
			std::uint32_t cksum;
	public:
		CRCMessage();
		CRCMessage(const std::array<uint8_t, UUID_SIZE>& idArray, const std::uint32_t size, const std::string& name, const std::uint32_t cksum);
		~CRCMessage();
		std::string getId() const;
		std::uint32_t getSize() const;
		std::string getName() const;
		std::uint32_t getCksum() const;
	};
#pragma pack(pop)


/*data of this client*/
class Client {
	private:
		std::string name;
		std::string uuid;
		std::string key;

	public:

		Client();
		Client(const std::string& name, const std::string& uuid, const std::string& key);
		Client(const Client& other);
		Client& operator=(const Client& other);
		~Client();
		std::string getName() const;
		std::string getUuid() const;
		std::string getKey() const;
};



