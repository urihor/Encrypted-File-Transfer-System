#pragma once

#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "cksum.h"
#include "structs.h"

#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <fstream>
#include <filesystem>
#include <array>
#include <vector>

static const int TIMES_TO_SEND = 4;
static const uint32_t FIXED_SIZE_IN_PACKET = 267;
static const int NOT_SUCCESS = -1;
static const int SUCCESS = 0;
static const int AES_LENGTH = 32;
static const uint16_t REGISTRATION_REQUEST = 1025;
static const uint16_t SEND_PUB_KEY = 1026;
static const uint16_t RECONNECT_REQUEST = 1027;
static const uint16_t SEND_FILE = 1028;
static const uint16_t CORRECT_CRC = 1029;
static const uint16_t RESEND = 1030;
static const uint16_t FAILED_AND_FINISH = 1031;
static const uint16_t FAILED_REGISTRATION = 1601;
static const uint16_t SUCCESSFUL_RECONNECT = 1605;
static const uint16_t FAILED_RECONNECT = 1606;
static const uint16_t GENERIC_ERROR = 1607;


using boost::asio::ip::tcp;

bool checkLegality(const std::string& name, const std::string& filePath);

void printHeader(const RecievedHeader& received_header);

void SendingHeader(tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray, const uint16_t code, const uint32_t size);

void createKeyFile(const std::string& base64key);

void createMeFile(const std::string& name, const std::string& uuid, const std::string& base64key);

std::string getNumbers(const std::string& checksum);

int sendThePackets(const std::string& ciphertext, const uint32_t after, const uint32_t before, const uint16_t numOfPackets, const std::string& filePath, tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray, const std::string& checksum);

void finish(const int counter, const std::string& filePath, tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray);

void sendFile(const std::string& filePath, AESWrapper& aes, const std::array<uint8_t, UUID_SIZE>& idArray, tcp::socket& sock);

std::string getFile(const std::string& filePath);

std::string getKey();

Client createKey(tcp::socket& sock, const std::string& name);

Client reconnect(tcp::socket& sock);

Client firstConnect(tcp::socket& sock, const std::string& name);

int startClient(const std::string& ip, const std::string& port, const std::string& name, std::string filePath);
