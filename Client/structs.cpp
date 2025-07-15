#include "structs.h"

	SendHeader::SendHeader(const std::array<uint8_t, UUID_SIZE>& idArray, const uint16_t code, const uint32_t size) {
		for (int i = 0; i < UUID_SIZE; i++) {
			this->idArray[i] = idArray[i];
		}
		version = VERSION;
		this->code = code;
		payloadSize = size;

	}

	SendHeader::~SendHeader() {

	}

	/*get the uuid in string*/
	std::string SendHeader::getId() const{ 
		std::ostringstream ss;
		for (const auto& byte : idArray) {
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}
		return ss.str();
	}

	std::uint16_t SendHeader::getCode() const{
		return code;
	}

	std::uint32_t SendHeader::getPayloadSize() const{
		return payloadSize;
	}





	RecievedHeader::RecievedHeader() {
		version = 0;
		this->code = 0;
		payloadSize = 0;
	}

	RecievedHeader::RecievedHeader(const uint8_t version, const uint16_t code, const uint32_t size) {
		this->version = version;
		this->code = code;
		payloadSize = size;

	}

	RecievedHeader::~RecievedHeader() {

	}

	std::uint8_t RecievedHeader::getVersion() const{
		return version;
	}

	std::uint16_t RecievedHeader::getCode() const{
		return code;
	}

	std::uint32_t RecievedHeader::getPayloadSize() const{
		return payloadSize;
	}





	FilePacket::FilePacket(const uint32_t afterSize, const uint32_t beforeSize, const uint16_t current, const uint16_t total, const std::string& path, const std::string& message) {
		this->afterSize = afterSize;
		this->beforeSize = beforeSize;
		this->current = current;
		this->total = total;
		size_t i;
		for (i = 0; i < path.size() ; i++) {
			this->path[i] = path[i];
		}
		for (i = 0; i < message.size() ; i++) {
			this->message[i] = message[i];
		}
	}

	FilePacket::~FilePacket() {

	}






	KeyPacket::KeyPacket(const std::string& name, const std::string& key) {
		size_t i;
		for (i = 0; i < name.size(); ++i) {
			this->name[i] = name[i];
		}
		if (i < this->name.size()) {
			this->name[i] = '\0';
		}
		for (i = 0; i < key.size(); ++i) {
			this->key[i] = key[i];
		}
	}

	KeyPacket::~KeyPacket() {

	}





	CRCMessage::CRCMessage() {
		idArray.fill(0);
		size = 0;
		cksum = 0;
		fileName.fill('\0');
	}

	CRCMessage::CRCMessage(const std::array<uint8_t, UUID_SIZE>& idArray, const std::uint32_t size, const std::string& name, const std::uint32_t cksum) {
		this->idArray = idArray;
		this->size = size;
		for (size_t i = 0; i < name.size(); i++) {
			this->fileName[i] = name[i];
		}
		this->cksum = cksum;
	}

	CRCMessage::~CRCMessage() {

	}

	std::string CRCMessage::getId() const{
		std::ostringstream ss;
		for (const auto& byte : idArray) {
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		}
		return ss.str();
	}

	std::uint32_t CRCMessage::getSize() const {
		return size;
	}

	std::string CRCMessage::getName() const {
		std::string str ="";
		for (char c : fileName) {
			str += c;
		};
		return str;
	}

	std::uint32_t CRCMessage::getCksum() const {
		return cksum;
	}





	Client::Client() {
		this->name = "";
		this->uuid = "";
		this->key = "";
	}

	Client::Client(const std::string& name, const std::string& uuid, const std::string& key) {
		this->name = name;
		this->uuid = uuid;
		this->key = key;
	}

	Client::Client(const Client& other) {
		this->name = other.name;
		this->uuid = other.uuid;
		this->key = other.key;
	}

	Client& Client::operator=(const Client& other) {

		if (this == &other) {
			return *this;
		}
		this->name = other.name;
		this->uuid = other.uuid;
		this->key = other.key;

		return *this;
	}

	Client::~Client() {

	}

	std::string Client::getName() const{
		return name;
	}

	std::string Client::getUuid() const{
		return uuid;
	}

	std::string Client::getKey() const{
		return key;
	}
