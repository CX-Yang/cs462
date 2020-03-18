#include "Blowfish.cc"
#include "Sockets.cc"

//#define DEBUG

int main()
{
	string ks;
#ifdef DEBUG
	// Prompt user for Ks (Session Key)
	cout << "Please enter the Session Key (Ks): ";
	// Store input Ks to variable
	cin >> ks;
	cin.ignore();
#else
	ks = generateRandomSessionKey();

#endif // DEBUG
	// Prompt user for Ka (InitiatorA private key)
	cout << "Please enter the A's Private Key (Ka): ";

	// Store input Ka to variable
	string ka;
	cin >> ka;
	cin.ignore();
	// Prompt user for Kb (ResponderB private key)
	cout << "Please enter the B's Private Key (Kb): ";

	// Store input Kb to variable
	string kb;
	cin >> kb;
	cin.ignore();
	// Open up a port to wait for A to connect to
	int sockfd = setupServerSocket(string("9500"));

	// Wait the request from A:
	int clientSocket = awaitConnection(sockfd);

	// Read the request from A:
	string clientInput = readString(clientSocket);

	// Break up the request into it's parts (Request|NonceA)
	vector<string> requestParts;
	splitResponse(clientInput, requestParts);

	// The first item in the vector will be the Request

	// Print to console the following:
	// NonceA
	// Ks (Session Key)
	cout << "NonceA: " << requestParts[1] << endl;
	cout << "Ks (Session Key): " << ks << endl;

	// Use blowfish to encrypt the Ks  and IDa (Session key and IDa)
	// using B's Key.
	vector<char> kbVector(kb.begin(), kb.end());
	Blowfish bfKb(kbVector);

	string ksIda = ks + "|IDa";
	vector<char> ksIdaVector(ksIda.begin(), ksIda.end());

	vector<char> eKsIDaVector = bfKb.Encrypt(ksIdaVector);

	string eKsIDa(eKsIDaVector.begin(), eKsIDaVector.end());

	// Use blowfish to encrypt (Ks | Request | resultAbove)
	// using A's key.
	vector<char> kaVector(ka.begin(), ka.end());
	Blowfish bfKa(kaVector);
	string ksRequesteKsIDa = ks + '|' + requestParts[0] + '|' + eKsIDa;

	vector<char> ksRequesteKsIDaVector(ksRequesteKsIDa.begin(), ksRequesteKsIDa.end());
	vector<char> ksRequestBEncryptVector = bfKa.Encrypt(ksRequesteKsIDaVector);

	string ksRequestBEncrypt(ksRequestBEncryptVector.begin(), ksRequestBEncryptVector.end());

	// Return the responce to A
	writeStringEncrypted(ksRequestBEncrypt, clientSocket, bfKa);

	/// Wait for A to finish reading
	readIntEncrypted(clientSocket, bfKa);

	// Do clean up
	close(clientSocket);
	close(sockfd);

	// fin.
	return 0;

}
