#include "client.h"


int main(int argc, char* argv[]) {

	try {
		ClientSession client(argc, argv);
		return client.startClientSession();
	}
	catch (const std::exception& error) {
		std::cerr << "Exception: " << error.what() << std::endl;
		return -1;
	}
}