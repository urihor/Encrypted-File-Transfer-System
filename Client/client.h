#pragma once
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>

class ClientSession {
private:
    std::string ip;
    std::string port;
    std::string name;
    std::string filePath;
    int status;

public:
    ClientSession(int argc, char* argv[]);
    ~ClientSession();

    int startClientSession();

private:
    bool checkLegality(const std::string& name, const std::string& filePath);
};