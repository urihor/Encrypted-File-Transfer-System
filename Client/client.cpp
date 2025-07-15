#pragma once
#include "funcs.h"
#include "client.h"



ClientSession::ClientSession(int argc, char* argv[]) {

    /*open the file "transfer.info" and read it*/
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(argv[0]));
    std::filesystem::current_path(exePath.parent_path());
    std::ifstream transferFile("transfer.info");

    if (!transferFile.is_open()) {
        throw std::runtime_error("Failed to open transfer.info");
    }

    std::string line;
    std::getline(transferFile, line);
    ip = line.substr(0, line.find(':'));
    port = line.substr(line.find(':') + 1);

    std::getline(transferFile, name);
    std::getline(transferFile, filePath);

    transferFile.close();
    status = 0;
}

ClientSession::~ClientSession() {

}

int ClientSession::startClientSession() {

    if (checkLegality(name, filePath)) {
        status = startClient(ip, port, name, filePath);
    }
    return status;
}

/*check that the name of the client and the name of the path are not too long*/
bool ClientSession::checkLegality(const std::string& name, const std::string& filePath) {

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



