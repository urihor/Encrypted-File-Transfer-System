#include "funcs.h"

/*check that the name of the client and the name of the path are not too long*/
bool checkLegality(const std::string& name, const std::string& filePath) {

	if (name.length() > MAX_NAME) {
		std::cout << "name must be less than 256 characters" << std::endl;
		return false;
	}
	size_t pos = filePath.find_last_of("/\\");  // check that the name of the file excludes the full path is less than 256 chars  
	if (filePath.length() - pos > MAX_FILE_NAME) {
		std::cout << "filePath must be less than 256 characters" << std::endl;
		return false;
	}
	return true;
}

void printHeader( const RecievedHeader& received_header) {
	std::cout << "Received header - Version: " << static_cast<int>(received_header.getVersion())
		<< ", Code: " << received_header.getCode()
		<< ", Payload Size: " << received_header.getPayloadSize() << std::endl;
}

/*send an header and print it*/
void SendingHeader(tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray, const uint16_t code, const uint32_t size) {
	SendHeader myHeader(idArray, code, size);
	boost::asio::write(sock, boost::asio::buffer(&myHeader, sizeof(myHeader)));
	std::cout << "Sended header - Version: " << VERSION
		<< ", Code: " << myHeader.getCode()
		<< ", Payload Size: " << myHeader.getPayloadSize() << ", Id: " << myHeader.getId() << std::endl << std::endl;
}

/* create priv.key and write the private key into it*/
void createKeyFile(const std::string& base64key) {
	try {
		std::ofstream keyFile("priv.key", std::ios::binary);

		// Check if the file is open
		if (keyFile.is_open()) {
			// Write the string to the file
			keyFile << base64key;
			// Close the file
			keyFile.close();
			std::cout << "File 'priv.key' created and written successfully." << std::endl;
		}
	}

	catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
	}
}

/*create me.info and write the name, uuid and the private key into it*/
void createMeFile(const std::string& name, const std::string& uuid, const std::string& base64key) {
	try {
		std::ofstream meFile("me.info", std::ios::binary);
		// Check if the file is open
		if (meFile.is_open()) {
			// Write the string to the file
			meFile << name << std::endl;
			meFile << uuid << std::endl;
			meFile << base64key << std::endl;
			// Close the file
			meFile.close();
			std::cout << "File 'me.info' created and written successfully." << std::endl << std::endl;
		}
	}
	catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
	}
}

/*extracts value of crc from the returning string from the function readfile in cksum_new.cpp */
std::string getNumbers(const std::string& checksum) {
	std::string result;
	for (char ch : checksum) {
		// Check if the character is a digit or the first space after digits
		if (std::isdigit(ch)) {
			result += ch;
		}
		else if (result.size() > 0) {
			// Stop when a space is encountered after digits
			break;
		}
	}
	return result;
}

int sendThePackets(const std::string& ciphertext, const uint32_t after, const uint32_t before, const uint16_t numOfPackets, const std::string& filePath, tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray, const std::string& checksum) {
	int counter = 1;
	std::cout << "sending the file now" << std::endl << std::endl;
	while (counter <= TIMES_TO_SEND) {
		int currentPacket = 1;
		/*get a chunk from the encrypted file and send it */
		for (int i = 0; i < ciphertext.size(); i += CHANGING_SIZE_IN_PACKET) {
			std::string chunk = ciphertext.substr(i, CHANGING_SIZE_IN_PACKET);
			FilePacket myPacket(after, before, currentPacket, numOfPackets, filePath, chunk);
			SendingHeader(sock, idArray, SEND_FILE, FIXED_SIZE_IN_PACKET + CHANGING_SIZE_IN_PACKET);
			boost::asio::write(sock, boost::asio::buffer(&myPacket, sizeof(myPacket)));
			currentPacket++;
		}

		/*get the crc from the server*/
		RecievedHeader received_header;
		CRCMessage message{};
		sock.read_some(boost::asio::buffer(&received_header, sizeof(received_header)));
		printHeader(received_header);
		if (received_header.getCode() == GENERIC_ERROR) {
			std::cout << "Unexcepted error in server " << std::endl;
			exit(0);
		}
		sock.read_some(boost::asio::buffer(reinterpret_cast<char*>(&message), received_header.getPayloadSize()));

		// Print the unpacked data
		std::cout << "id is: " << message.getId() << " contents size is: " << message.getSize() << " filename is: " << message.getName() << " checksum is:" << message.getCksum() << std::endl << std::endl;

		std::string checksumNumbers = getNumbers(checksum);
		if (message.getCksum() == stoll(checksumNumbers)) {  // check if the crc calculated by the client is equal to the crc sent from server
			std::cout << "file sent successfully" << std::endl << std::endl;
			break;
		}
		else {
			std::cout << "server responded with an error " << std::endl;
			if (counter < TIMES_TO_SEND) { // in the first 3 times, send code 1030 
				std::cout << "try to send another time " << std::endl << std::endl;
				SendingHeader(sock, idArray, RESEND, MAX_FILE_NAME);
				std::array<char, MAX_FILE_NAME>path = { '\0' };
				for (size_t i = 0; i < filePath.size(); ++i) {
					path[i] = filePath[i];
				}
				boost::asio::write(sock, boost::asio::buffer(path, sizeof(path)));
			}

		}
		counter++;
	}
	return counter;
}

void finish(const int counter, const std::string& filePath, tcp::socket& sock, const std::array<uint8_t, UUID_SIZE>& idArray) {
	std::array<char, MAX_FILE_NAME>path = { '\0' };
	for (size_t i = 0; i < filePath.size(); ++i) {
		path[i] = filePath[i];
	}
	if (counter <= TIMES_TO_SEND) {  // the file was sent successfuly in one of the first 4 times 
		SendingHeader(sock, idArray, CORRECT_CRC, MAX_FILE_NAME);
	}
	else {  // the file wasn't sent successfuly
		std::cout << "failed to send the file" << std::endl << std::endl;
		SendingHeader(sock, idArray, FAILED_AND_FINISH, MAX_FILE_NAME);
	}
	
	/*send the payload of 1029/1031 and get the message 1604 from server*/
	boost::asio::write(sock, boost::asio::buffer(path, sizeof(path)));
	RecievedHeader received_header;
	std::array<uint8_t, UUID_SIZE> getIdArray{};
	sock.read_some(boost::asio::buffer(&received_header, sizeof(received_header)));
	printHeader(received_header);
	if (received_header.getCode() == GENERIC_ERROR) {
		std::cout << "Unexcepted error in server " << std::endl;
		exit(1);
	}
	sock.read_some(boost::asio::buffer(getIdArray, received_header.getPayloadSize()));
	

	if (counter > TIMES_TO_SEND) {  // fatal error - the file wasn't sent successfuly
		std::cout << "fatal error: the server didn't get the file correctly" << std::endl;
		exit(1);
	}
			
}

void sendFile(std::string& filePath, AESWrapper& aes, const std::array<uint8_t, UUID_SIZE>& idArray, tcp::socket& sock) {

	std::string checksum = readfile(filePath);
	std::cout << "checksum of the file is: " << checksum << std::endl << std::endl;
	std::string file_contents = getFile(filePath);
	std::cout << "File size before encryption: " << file_contents.size() << " bytes" << std::endl;
	std::string ciphertext = aes.encrypt(file_contents.c_str(), file_contents.length());
	std::cout << "after encryption:  " << ciphertext.size() << " bytes" << std::endl;

	uint32_t after = static_cast<uint32_t>(ciphertext.size());
	uint32_t before = static_cast<uint32_t>(file_contents.size());
	int num = (ciphertext.size() / (CHANGING_SIZE_IN_PACKET + 1) + 1);

	if (after > 4277403915) {
		std::cout << "the size of the file is too big for maximum 65535 packets" << std::endl;
		return;
	}
	
	if (num > 65535) {
		std::cout << "too many packets, try to increase CHANGING_SIZE_IN_PACKET" << std::endl;
		return;
	}
	uint16_t numOfPackets = static_cast<uint16_t>(num);

	size_t pos = filePath.find_last_of("/\\");  // send only the name of the file(not all the path)
	filePath = filePath.substr(pos + 1);
	std::cout << "name of file that sent to the server: " << filePath << std::endl << std::endl;
	int counter = sendThePackets(ciphertext, after, before, numOfPackets, filePath, sock, idArray, checksum);
	finish(counter, filePath, sock, idArray);
}

/*read the contents of the file into buffer and return it as string*/
std::string getFile(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "Error opening file: " << filePath << std::endl;
		return NULL;
	}

	std::ostringstream buffer;
	buffer << file.rdbuf();
	std::string file_contents = buffer.str();

	// Close the file
	file.close();
	return file_contents;
}

/*get the key from the file priv.key*/
std::string getKey() {
	try {
		std::ifstream keyFile("priv.key");

		// Check if the file is open

		std::stringstream strStream;
		strStream << keyFile.rdbuf(); //read the file
		std::string base64key = strStream.str(); //str holds the content of the file
		// Close the file
		keyFile.close();
		return base64key;
	}
	catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
		return "";
	}
}

/*get uuid from server, create rsa key and send the public key to the server*/
Client createKey(tcp::socket& sock, const std::string& name) {
	std::string uuid;
	std::string base64key;
	int status = 0;
	std::array<uint8_t, UUID_SIZE> idArray{};

	/*get the uuid from the server*/
	sock.read_some(boost::asio::buffer(idArray));
	std::ostringstream ss;
	for (const auto& byte : idArray) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	}
	uuid = ss.str();
	std::cout << "UUID from the server: " << uuid << std::endl;
	std::cout << std::endl;

	/*create rsa key*/
	RSAPrivateWrapper rsapriv;
	base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());

	createKeyFile(base64key);
	createMeFile(name, uuid, base64key);

	/*send public key and uuid to the server*/
	std::string pubkey = rsapriv.getPublicKey();

	for (int i = 0; i < UUID_SIZE; ++i) {
		std::string hexPair = uuid.substr(2 * i, 2);
		idArray[i] = std::stoi(hexPair, nullptr, 16);
	}

	std::cout << "send public key" << std::endl;
	SendingHeader(sock, idArray, SEND_PUB_KEY, MAX_NAME + SIZE_OF_PUB_KEY);
	KeyPacket contents(name, pubkey);
	boost::asio::write(sock, boost::asio::buffer(&contents, sizeof(contents)));

	Client client(name, uuid, rsapriv.getPrivateKey()); // create a client object contains the data of this client
	return client;
}

Client reconnect(tcp::socket& sock) {
	std::array<uint8_t, UUID_SIZE> idArray{};
	std::string uuid;
	std::string base64key;

	std::string name;
	std::array<char, MAX_NAME>nameToSend = { '\0' };

	/*get the data of the client from the files: me.info and priv.key*/
	try {
		std::ifstream meFile("me.info");

		// Check if the file is open
		if (meFile.is_open()) {
			std::getline(meFile, name);
			std::getline(meFile, uuid);
			// Close the file
			meFile.close();

		}

	}
	catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
	}
	base64key = getKey();

	for (size_t i = 0; i < name.size(); i++) {
		nameToSend[i] = name[i];
	}

	for (int i = 0; i < UUID_SIZE; i++) {
		std::string hexPair = uuid.substr(2 * i, 2);
		idArray[i] = std::stoi(hexPair, nullptr, 16);
	}

	SendingHeader(sock, idArray, RECONNECT_REQUEST, MAX_NAME);
	boost::asio::write(sock, boost::asio::buffer(nameToSend, sizeof(nameToSend)));
	Client client(name, uuid, Base64Wrapper::decode(base64key));
	return client;

}

Client firstConnect(tcp::socket& sock, const std::string& name) {

	std::array<uint8_t, UUID_SIZE> idArray{};
	std::array<char, MAX_NAME>nameToSend = { '\0' };

	for (size_t i = 0; i < name.size(); ++i) {
		nameToSend[i] = name[i];
	}
	SendingHeader(sock, idArray, REGISTRATION_REQUEST, MAX_NAME);
	boost::asio::write(sock, boost::asio::buffer(nameToSend, sizeof(nameToSend)));

	RecievedHeader received_header;
	sock.read_some(boost::asio::buffer(&received_header, sizeof(received_header)));
	printHeader(received_header);

	if (received_header.getCode() == FAILED_REGISTRATION) {
		std::cout << "can't connect with that name" << std::endl;
		exit(0);
	}

	std::cout << "connection successful" << std::endl;
	Client client = createKey(sock, name);
	return client;
}

int startClient(const std::string& ip, const std::string& port, const std::string& name, std::string filePath) {
	
	std::string uuid;
	std::array<uint8_t, UUID_SIZE> idArray = { 0 };
	Client client;
	uint32_t size = 0;

	try {

		boost::asio::io_context io_context;
		tcp::socket sock(io_context);
		tcp::resolver resolver(io_context);
		boost::asio::connect(sock, resolver.resolve(ip, port));

		std::cout << "name of client: " << name << " . path of file: " << filePath << std::endl << std::endl;

		if (!std::filesystem::exists("me.info")) { 
			std::cout << "request to connect" << std::endl << std::endl;
			client = firstConnect(sock, name);	
		}
		else {
			std::cout << "request to reconnect" << std::endl;
			client = reconnect(sock);
		}

		RecievedHeader received_header;
		sock.read_some(boost::asio::buffer(&received_header, sizeof(received_header)));
		printHeader(received_header);
		size = received_header.getPayloadSize();

		if (received_header.getCode() == FAILED_REGISTRATION) {  // for case that reconnect failed and the name is already used 
			std::cout << "can't reconnect with that name" << std::endl;
			exit(0);
		}
		else if (received_header.getCode() == GENERIC_ERROR) {  // error occured in the db
			std::cout << "unexcepted error in server " << std::endl;
			exit(1);
		}
		else if (received_header.getCode() == FAILED_RECONNECT) {  // signed as new client, need to send public key
			std::cout << "reconnect failes, connected as new client" << std::endl;
			client = createKey(sock, name);
			RecievedHeader received_header;
			sock.read_some(boost::asio::buffer(&received_header, sizeof(received_header)));
			printHeader(received_header);
			if (received_header.getCode() == GENERIC_ERROR) {  // error occured in the db
				std::cout << "Unexcepted error in server " << std::endl;
				exit(1);
			}
			size = received_header.getPayloadSize();
		}
		else if (received_header.getCode() == SUCCESSFUL_RECONNECT) {
			std::cout << "reconnection successful" << std::endl;
		}

		std::vector<char> receivedData(size);
		sock.read_some(boost::asio::buffer(receivedData,size));
		std::string aesReceived(receivedData.begin() + UUID_SIZE, receivedData.end());
		std::cout << "got aes key from server" << std::endl << std::endl;

		RSAPrivateWrapper rsapriv(client.getKey());
		uuid = client.getUuid();
		for (int i = 0; i < UUID_SIZE; ++i) {
			std::string hexPair = uuid.substr(2 * i, 2);
			idArray[i] = std::stoi(hexPair, nullptr, 16);
		}
		/*decrypt the aes key by the private key*/
		std::string decrypted = rsapriv.decrypt(aesReceived);  
		const unsigned char* ucharPtr = reinterpret_cast<const unsigned char*>(decrypted.c_str());
		AESWrapper aes(ucharPtr, AES_LENGTH);

		sendFile(filePath, aes, idArray, sock);
		return SUCCESS;
	}
	
	catch (std::exception& error) {
		std::cerr << "Exception: " << error.what() << "\n";
		return NOT_SUCCESS;
	}
}
