#include <fstream>
#include "Blowfish.cc"
#include "Sockets.cc"

//#define DEBUG
//#define DO_NOT_DECRYPT_FILE
//#define DEBUG_PLAIN_TEXT

long nonceFunction(long nonce) {
	const long A = 48271;
	const long M = 2147483647;
	const long Q = M / A;
	const long R = M % A;

	static long state = 1;
	long t = A * (state % Q) - R * (state / Q);

	if (t > 0)
		state = t;
	else
		state = t + M;
	return (long)(((double)state / M) * nonce);
}

int main() {
	// Store input NonceB to variable
	string nonceB;

#ifdef DEBUG
	// Prompt user for NonceB:
	cout << "Please enter NonceB (N2): ";
	cin >> nonceB;
	cin.ignore();
#else
	nonceB = to_string(generateRandomLong());
#endif // DEBUG

	// Prompt user for Kb:
	cout << "Please enter the B's Private Key (Kb): ";

	// Store input Kb to variable
	string kb;
	cin >> kb;
	cin.ignore();

	// Open up a socket and wait to connect to A
	int sockfd = setupServerSocket(string("9501"));

	// Wait to hear from A
	int clientSocket = awaitConnection(sockfd);

	// Setup B's Blowfish
	Blowfish bfKb(vector<char>(kb.begin(), kb.end()));

	// Read what A has sent
	string encryptedAResponse = readString(clientSocket);
	vector<char> encryptedAResponseVector(encryptedAResponse.begin(), encryptedAResponse.end());

	// Decrypt what A sent using Kb (B's key)
	vector<char> aResponseVector = bfKb.Decrypt(encryptedAResponseVector);
	string aResonse(aResponseVector.begin(), aResponseVector.end());

	// Break up the response into it's parts (Ks|IDa)
	// The requestParts should look like (Ks|IDa)
	vector<string> requestParts;
	splitResponse(aResonse, requestParts);

	// Store the Ks
	string ks = requestParts[0];

	// Print Ks
	cout << "Ks (Session Key): " << ks << endl;

	// Print NonceB
	cout << "NonceB: " << nonceB << endl;

	// Encrypt NonceB with the Ks
	vector<char> nonceBVector(nonceB.begin(), nonceB.end());
	vector<char> ksVector(ks.begin(), ks.end());
	Blowfish bfKs(ksVector);
	vector<char> encryptedNonceBVector = bfKs.Encrypt(nonceBVector);
	string encryptedNonceB(encryptedNonceBVector.begin(), encryptedNonceBVector.end());

	// Send result of above to A
	writeStringEncrypted(encryptedNonceB, clientSocket, bfKs);

	// Read what A has sent
	vector<char> encryptedFNonce2Vector = readStringEncrypted(clientSocket, bfKs);

	// Decrypt what A sent
	vector<char> fNonce2Vector = bfKs.Decrypt(encryptedFNonce2Vector);
	string fNonce2(fNonce2Vector.begin(), fNonce2Vector.end());

	//convert nonceB to a long for the nonceFunction
	long bNonce = atol(nonceB.c_str());
	// Store this.function(Nonce2) in a variable
	long myFNonce2 = nonceFunction(bNonce);

	// Compare this.function(Nonce2) to what A sent
	// If they match we are good and both A and B have the session key
	string myFNonce2String = to_string(myFNonce2);

	if (myFNonce2String.compare(fNonce2) == 0) {
		// Read what A has sent
		size_t chunks = readIntEncrypted(clientSocket, bfKs);
		ofstream savefile("/tmp/networks", ios::trunc | ios::binary | ios::out);

		if (savefile.is_open()) {
			while (chunks) {
				vector<char> tempBuffer = readStringEncrypted(clientSocket, bfKs);

#ifdef DO_NOT_DECRYPT_FILE
				vector<char> fileHexVector = tempBuffer;
				string fileHex(fileHexVector.begin(), fileHexVector.end());
				string fileText = hexToString(fileHex);
#else 
				// Decrypt what A has sent using Ks
				vector<char> fileHexVector = bfKs.Decrypt(tempBuffer);
				string fileHex(fileHexVector.begin(), fileHexVector.end());
				string fileText = hexToString(fileHex);
#endif // DO_NOT_DECRYPT_FILE


#ifdef DEBUG
				// Print what A has sent as Hex
				cout << "Encrypted Hex Chunk: ";
				string encryptedFile(tempBuffer.begin(), tempBuffer.end());
				string encryptedFileHex = stringToHex(encryptedFile);
				for (auto it = encryptedFileHex.begin(); it != encryptedFileHex.end(); ++it)
				{
					if (!((it - encryptedFileHex.begin()) % 25)) {
						cout << endl;
					}
					cout << *it;
				}
				cout << endl;

				// Print what A sent unencrypted in Hex
				cout << "Hex Chunk: ";
				for (auto it = fileHexVector.begin(); it != fileHexVector.end(); ++it)
				{
					if (!((it - fileHexVector.begin()) % 25)) {
						cout << endl;
					}
					cout << *it;
				}
				cout << endl;
#endif // DEBUG
#ifdef DEBUG_PLAIN_TEXT
				// Print the Plain Text Chunk:
				cout << "Plain Text Chunk: ";
				for (auto it = fileText.begin(); it != fileText.end(); ++it)
				{
					if (!((it - fileText.begin()) % 25)) {
						cout << endl;
					}
					cout << *it;
				}
				cout << endl;
#endif // DEBUG_PLAIN_TEXT

				savefile.write(fileText.c_str(), fileText.size());
				chunks--;
			}

			savefile.close();
		}
		else {
			cout << "Something when wrong opening the file" << endl;
			cout << "Errno: " << errno << endl;
		}

	}
	else {
		cout << "Nonce2 Functions didn't match. Can't establish secure connection." << endl;
	}

	// Tell A we are done so the socket can be closed
	writeIntEncrypted(0, clientSocket, bfKs);

	// Do clean up
	close(clientSocket);
	close(sockfd);

	return 0;

}
