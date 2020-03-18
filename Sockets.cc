#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <unistd.h>

using namespace std;

// METHOD IMPLEMENTATION
string stringToHex(const string& in) {
	string hexString;
	hexString.reserve(in.length() << 1);

	char const hexChars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	for (size_t i = 0; i < in.length(); ++i)
	{
		char const byte = in[i];

		hexString += hexChars[(byte & 0xF0) >> 4];
		hexString += hexChars[(byte & 0x0F) >> 0];
	}
	return hexString;

}

unsigned char getHexValue(unsigned char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	else if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	else if ('A' <= c && c <= 'F')
		return c - 'A' + 10;
	else {
		cout << "Not a valid Hex Value" << endl;
		abort();
	}
}

string hexToString(const string& in) {
	string output;

	if ((in.length() % 2) != 0) {
		throw runtime_error("String is not valid length ...");
	}

	output.reserve(in.length() / 2);

	for (string::const_iterator it = in.begin(); it != in.end(); it++)
	{
		unsigned char c = getHexValue(*it);
		it++;
		c = (c << 4) + getHexValue(*it);
		output.push_back(c);
	}

	return output;
}

int setupServerSocket(string portno) {
	int sockfd;
	struct addrinfo hints, * servinfo, * p;
	int rv;
	bool bindSuccessful = false;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((rv = getaddrinfo(NULL, portno.c_str(), &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	// Loop through all the results and bind to the first and then exit
	p = servinfo;
	while (p != NULL && !bindSuccessful) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
			perror("socket");
			p = p->ai_next;
		}
		else if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("bind");
			p = p->ai_next;
		}
		else {
			bindSuccessful = true;
		}
	}

	freeaddrinfo(servinfo);

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, 1) == -1) {
		perror("listen");
		exit(1);
	}

	return sockfd;
}

int awaitConnection(int sockfd) {
	int numberConnectedNodes = 0;
	struct sockaddr_storage connectingAddress;
	socklen_t socketInSize;
	int newSocketFd;

	// Wait for a call
	while (numberConnectedNodes != 1) {  // main accept() loop
		socketInSize = sizeof connectingAddress;
		newSocketFd = accept(sockfd, (struct sockaddr*) & connectingAddress, &socketInSize);
		if (newSocketFd == -1) {
			perror("accept");
		}
		else {
			numberConnectedNodes += 1;
		}

	}
	return newSocketFd;
}

void writeInt(uint32_t x, int socket) {
	int convertedNumber = htonl(x);
	ssize_t n = send(socket, &convertedNumber, sizeof(convertedNumber), 0);
	if (n < 0) {
		printf("ERROR writing to socket\n");
		exit(1);
	}
}

void writeIntEncrypted(size_t x, int socket, Blowfish blowfish) {
	ostringstream ss;
	ss << setw(10) << setfill('0') << x;
	string sizeString = ss.str();
	string sh = stringToHex(sizeString);
	vector<char> sizeHexVector(sh.begin(), sh.end());
	vector<char> shv = blowfish.Encrypt(sizeHexVector);
	string eshv(shv.begin(), shv.end());
	ssize_t n = send(socket, eshv.c_str(), eshv.length(), 0);
	if (n < 0) {
		printf("ERROR writing to socket\n");
		exit(1);
	}
	if (static_cast<size_t>(n) != eshv.length()) {
		cout << "Not all the bytes were sent in writeIntEncrypted" << endl;
		exit(1);
	}
}

int readInt(int socket) {
	int received_int = 0;
	ssize_t n = recv(socket, &received_int, sizeof(received_int), 0);

	if (n < 0) {
		printf("ERROR reading from socket\n");
		exit(0);
	}

	return ntohl(received_int);
}

size_t readIntEncrypted(int socket, Blowfish blowfish) {
	string buffer;
	vector<char> tempBuffer(24);
	size_t size = 24;
	while (size) {

		ssize_t n = recv(socket, tempBuffer.data(), 24, 0);
		if (n < 0) {
			printf("ERROR reading from socket\n");
		}

		if (n == 0) {
			// The connection was closed on the other end
			// so set n to size to escape the loop.
			cout << "Connection closed. Exiting recv loop..." << endl;
			n = size;
		}

		buffer += string(tempBuffer.begin(), tempBuffer.end());
		size -= static_cast<size_t>(n);
	}
	// Decrypt sent using blowfish
	vector<char> fileHexVector = blowfish.Decrypt(vector<char>(buffer.begin(), buffer.end()));

	string fileHex(fileHexVector.begin(), fileHexVector.end());
	string fileText = hexToString(fileHex);

	size_t returnValue = 0;
	stringstream ss(fileText);
	ss >> returnValue;
	return returnValue;
}

void writeString(const string x, int socket) {
	writeInt(static_cast<uint32_t>(x.length()), socket);

	ssize_t n = send(socket, x.c_str(), x.length(), 0);
	if (n < 0) {
		printf("ERROR writing to socket\n");
		exit(1);
	}
}

void writeStringEncrypted(const string x, int socket, Blowfish blowfish) {
	writeIntEncrypted(x.length(), socket, blowfish);
	ssize_t n = send(socket, x.c_str(), x.length(), 0);
	if (n < 0) {
		printf("ERROR writing to socket\n");
		exit(1);
	}
	if (static_cast<size_t>(n) != x.length()) {
		cout << "Not all the bytes were sent in writeStringEncrypted" << endl;
		exit(1);
	}

}

string readString(int socket) {
	string receivedString;
	int stringSize = readInt(socket);

	vector<char> buffer(stringSize);

	ssize_t n = recv(socket, buffer.data(), stringSize, 0);

	if (n < 0) {
		printf("ERROR reading from socket\n");
		exit(0);
	}
	else {
		receivedString.assign(buffer.data(), buffer.size());
	}

	return receivedString;
}

vector<char> readStringEncrypted(int socket, Blowfish blowfish) {
	size_t stringSize = readIntEncrypted(socket, blowfish);
	char buffer[stringSize];
	size_t received = 0;

	while (received < stringSize) {
		ssize_t n = recv(socket, buffer + received, stringSize - received, 0);
		if (n < 0) {
			cout << "ERROR reading from socket" << endl;
		}
		received += n;
	}

	return vector<char>(buffer, buffer + stringSize);
}

int callServer(string host, string portno) {
	int sockfd;
	struct addrinfo hints, * servinfo, * p;
	bool connectedSuccessfully = false;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(host.c_str(), portno.c_str(), &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(1);
	}

	p = servinfo;
	// Loop until we connect successfully or run out of items in the list
	while (p != NULL && !connectedSuccessfully) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
			perror("socket");
			p = p->ai_next;
		}
		else if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("connect");
			cout << "errorno" << errno << endl;
			close(sockfd);
			p = p->ai_next;
		}
		else {
			connectedSuccessfully = true;
		}
	}

	if (p == NULL) {
		fprintf(stderr, "failed to connect\n");
		exit(2);
	}

	freeaddrinfo(servinfo);

	return sockfd;
}

void splitResponse(const string& str, vector<string>& vector)
{
	stringstream ss(str);
	string token;
	while (std::getline(ss, token, '|')) {
		vector.push_back(token);
	}
}

long generateRandomLong() {
	// Per STL's advice & slides:
	// https://channel9.msdn.com/Events/GoingNative/2013/rand-Considered-Harmful
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<long> dist(0, __LONG_MAX__);
	return dist(mt);
}

string generateRandomSessionKey() {
	string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	default_random_engine rd(random_device{}());
	uniform_int_distribution<> dist(0, 62);
	auto randchar = [chars, &dist, &rd]() {return chars[dist(rd)]; };
	string test(10, 0);
	generate_n(test.begin(), 10, randchar);
	return test;
}