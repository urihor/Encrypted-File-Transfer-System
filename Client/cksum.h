#pragma once

#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>

#define UNSIGNED(n) (n & 0xffffffff)

unsigned long memcrc(char* b, size_t n);
std::string readfile(std::string fname);


