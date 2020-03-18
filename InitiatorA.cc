#include <fstream>
#include <sys/stat.h>
#include "Blowfish.cc"
#include "Sockets.cc"

//#define DEBUG
//#define DO_NOT_ENCRYPT_FILE

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
	string nonceA;

#ifdef DEBUG
	// Prompt user for NonceA:
	cout << "Please enter NonceA (N1): ";

	// Store input NonceA to variable
	cin >> nonceA;
	cin.ignore();
#else 
	nonceA = to_string(generateRandomLong());
#endif // DEBUG

	// Prompt user for Ka (InitiatorA private key)
	cout << "Please enter the A's Private Key (Ka): ";

	// Store input Ka to variable
	string ka;
	cin >> ka;
	cin.ignore();
	// Connect to KDC
	int sockfd = callServer(string("thing1.cs.uwec.edu"), string("9500"));

	// Send request to KDC for Ks to B:
	// This should include Request | NonceA
	string request1 = "Request|" + nonceA;
	writeString(request1, sockfd);

	// Construct Blowfish object to encrypt and decrypt
	Blowfish bfKa(vector<char>(ka.begin(), ka.end()));

	// Read KDC's response and store it in a variable
	vector<char> encryptedKDCResponseVector = readStringEncrypted(sockfd, bfKa);

	/// Tell KDC we have all of the message
	writeIntEncrypted(0, sockfd, bfKa);

	// Decrypt what KDC sent using Ka (A's key)
	vector<char> kdcResponseVector = bfKa.Decrypt(encryptedKDCResponseVector);

	string kdcResponse(kdcResponseVector.begin(), kdcResponseVector.end());

	// Break up the request into it's parts (Request|NonceA)
	// The requestParts should look like (Ks | Request | eKsIDa)
	vector<string> requestParts;
	splitResponse(kdcResponse, requestParts);

	// Print the Ks and NonceA
	cout << "NonceA: " << nonceA << endl;
	cout << "Ks (Session Key): " << requestParts[0] << endl;

	// Close the socket to KDC
	close(sockfd);

	// Set up a socket to IDb
	sockfd = callServer(string("thing3.cs.uwec.edu"), string("9501"));

	// Send the remaining result from KDC ( Ekb(Ks, IDa) to IDb
	writeString(requestParts[2], sockfd);

	// Read what B has sent
	Blowfish bfKs(vector<char>(requestParts[0].begin(), requestParts[0].end()));
	vector<char> encryptedBResponseVector = readStringEncrypted(sockfd, bfKs);

	// Decrypt what B has sent using Ks
	vector<char> bResponseVector = bfKs.Decrypt(encryptedBResponseVector);
	string bResponse(bResponseVector.begin(), bResponseVector.end());

	//convert to long for the nonce function
	long bResp = atol(bResponse.c_str());

	// Print NonceB
	cout << "NonceB: " << bResp << endl;

	// Store function(NonceB) in a variable
	long functNonceB = nonceFunction(bResp);

	// Print f(NonceB)
	cout << "Nonce Function Resultant: " << functNonceB << endl;

	// Encrypt the f(NonceB) using Ks
	string fNonce = std::to_string(functNonceB);
	vector<char> fNonceVector(fNonce.begin(), fNonce.end());
	vector<char> encryptedFNonceVector = bfKs.Encrypt(fNonceVector);
	string encryptedFNonce(encryptedFNonceVector.begin(), encryptedFNonceVector.end());

	// Send encrypted f(NonceB) to B
	writeStringEncrypted(encryptedFNonce, sockfd, bfKs);

		// Prompt the user to enter text or a file
		cout << "Do you want to:" << endl;
		cout << "1: Enter string S (any length)" << endl;
		cout << "2: Enter a file path" << endl;

		int option = 0;
		cin >> option;
		while (cin.fail() || (option != 1 && option != 2 )) {
			cin.clear();
			cin.ignore(numeric_limits<streamsize>::max(),'\n');
			cout << "Do you want to:" << endl;
			cout << "1: Enter string S (any length)" << endl;
			cout << "2: Enter a file path" << endl;
			cin >> option;
		}
		cin.ignore();
		string input;
		if (option == 1) {
			cout << "Enter string S (any length): " << endl;
			getline(cin, input);

			string fileHex = stringToHex(input);
			// Encrypt hex using Ks (Session Key)
			cout << "File Hex: " << fileHex << endl;

			vector<char> encryptedFileHexVector = bfKs.Encrypt(vector<char>(fileHex.begin(), fileHex.end()));
			string encryptedFileHex(encryptedFileHexVector.begin(), encryptedFileHexVector.end());

			cout << "Encrypted Hex: " << stringToHex(encryptedFileHex) << endl;

			// Tell B how many chunks we are sending...
			writeIntEncrypted(1, sockfd, bfKs);
			// Send the encrypted hex to B
			writeStringEncrypted(encryptedFileHex, sockfd, bfKs);
		}
		else if (option == 2) {
			cout << "Enter a file path: " << endl;
			string filePath;
			cin >> filePath;
			cin.ignore();
			// Read the file that was input
			ifstream ifs(filePath, ios::binary | ios::in);

			if (not ifs) {
				cout << "Something went wrong and we couldn't open the file" << endl;
			}

			struct stat filestatus;
			stat(filePath.c_str(), &filestatus);

			size_t totalSize = filestatus.st_size;
			size_t chunkSize = 262144;

			size_t totalChunks = totalSize / chunkSize;
			size_t lastChunkSize = totalSize % chunkSize;

			if (lastChunkSize != 0) /* if the above division was uneven */
			{
				++totalChunks; /* add an unfilled final chunk */
			}
			else /* if division was even, last chunk is full */
			{
				lastChunkSize = chunkSize;
			}

			// Tell B how many chunks we are sending...
			writeIntEncrypted(totalChunks, sockfd, bfKs);
			// The loop through the chunks
			for (size_t chunk = 0; chunk < totalChunks; ++chunk)
			{
				size_t currentChunkSize =
					chunk == totalChunks - 1 /* if last chunk */
					? lastChunkSize /* then fill chunk with remaining bytes */
					: chunkSize; /* else fill entire chunk */

				vector<char> chunkData(currentChunkSize);
				ifs.read(&chunkData[0], /* address of buffer start */
					currentChunkSize); /* this many bytes is to be read */

#ifdef DO_NOT_ENCRYPT_FILE 
				string efhv = stringToHex(string(chunkData.begin(), chunkData.end()));
#else 
				string fh = stringToHex(string(chunkData.begin(), chunkData.end()));
				vector<char> efhv = bfKs.Encrypt(vector<char>(fh.begin(), fh.end()));
#endif // DO_NOT_ENCRYPT_FILE 

				string efh(efhv.begin(), efhv.end());
				writeStringEncrypted(efh, sockfd, bfKs);

			}
			ifs.close();
		}
	readIntEncrypted(sockfd, bfKs);

	// Do the clean up
	close(sockfd);

	return 0;

}
