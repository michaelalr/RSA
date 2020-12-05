#include <Windows.h>
#include <iostream>
#include <bitset>
#include <string>
#include <chrono>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

/*
* Generate RSA key pair.
*/
NTSTATUS keyGen(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* hKey, int keySize)
{
	NTSTATUS status;

	//Generate the key pair.
	status = BCryptGenerateKeyPair(hAlgorithm, hKey, keySize, 0);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptGenerateKeyPair with error code 0x%08x\n", status);
		return status;
	}

	//Finalize the key pair. The public/private key pair cannot be used until this function is called.
	status = BCryptFinalizeKeyPair(*hKey, 0);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptFinalizeKeyPair with error code 0x%08x\n", status);
		return status;
	}

	return status;
}

/*
* sign input1 with the chosen hash algo (BCRYPT_SHA1_ALGORITHM or BCRYPT_SHA256_ALGORITHM).
* verify the signature of input1 on input2 and check if get an error (iff input1 != input2) - 
* if we get an error - the signature is correct (work only for input1).
*/
NTSTATUS signMsg1VerifyMsg2(BCRYPT_KEY_HANDLE hKey, int signHash, char *input1, char *input2)
{
	NTSTATUS status;
	PBYTE pbSignature;
	ULONG sigLen, resLen;
	BCRYPT_PKCS1_PADDING_INFO pInfo;

	//Hardcode input1 to be signed and input2 to be verified:
	PBYTE msg1 = (PBYTE)input1, msg2 = (PBYTE)input2;
	ULONG msg1Len = strlen((char*)msg1), msg2Len = strlen((char*)msg2);

	//Retrieve the size of the buffer needed for the signature:
	status = BCryptSignHash(hKey, NULL, msg1, msg1Len, NULL, 0, &sigLen, 0);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptSignHash with error code 0x%08x\n", status);
		return status;
	}

	//Allocate a buffer for the signature:
	pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sigLen);
	if (pbSignature == NULL)
	{
		return -1;
	}

	//Use the user chosen SHA algorithm to create padding information:
	if (signHash == 1)
	{
		pInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;
	}
	else //sign_hash == 256
	{
		pInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	}

	//Create a signature - signing msg1:
	status = BCryptSignHash(hKey, &pInfo, msg1, msg1Len, pbSignature, sigLen, &resLen, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptSignHash with error code 0x%08x\n", status);
		return status;
	}

	//Verify the signature for msg1 - suppose to be true:
	status = BCryptVerifySignature(hKey, &pInfo, msg1, msg1Len, pbSignature, sigLen, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptVerifySignature with error code 0x%08x\n", status);
		return status;
	}

	//Verify the signature (of msg1) on msg2 - suppose to be false:
	status = BCryptVerifySignature(hKey, &pInfo, msg2, msg2Len, pbSignature, sigLen, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status) && strcmp(input1, input2) != 0) //Check if the verify on msg2 return true / false
	{
		std::cout << "CORRECT! Sign on msg1 and verify on msg2 - with the signature of msg1 - is invalid!" << std::endl;
	}
	else if (strcmp(input1, input2) == 0)
	{
		std::cout << "msg1 and msg2 are the same and have the same signature" << std::endl;
	}
	else
	{
		std::cout << "FAIL! Sign on msg1 and verify on msg2 - with the signature of msg1 - suppose to be invalid!" << std::endl;
		wprintf(L"Error: failed in BCryptVerifySignature with error code 0x%08x\n", status);
	}
	

	//Free the memory allocated for the signature.
	if (pbSignature != NULL)
	{
		HeapFree(GetProcessHeap(), 0, pbSignature);
		pbSignature = NULL;
	}

	return 0;
}

/*
* generate RSA key pair, sign input1 and verify input2 on input1's signature.
* if timeCheck == true, calculate the execute time of the functions keyGen() and signMsg1VerifyMsg2()
* and add them respectively to the references sumKeyGenTime and sumSignTime.
*/
int testVerifyKey(int keySize, int signHash, char *input1, char* input2, bool timeCheck, double &sumKeyGenTime, double &sumSignTime)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hRsaAlg;
	BCRYPT_KEY_HANDLE hKey = NULL;

	//Get the RSA algorithm provider from the Cavium CNG provider:
	std::cout << "Opening RSA algorithm" << std::endl;
	status = BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptOpenAlgorithmProvider with error code 0x%08x\n", status);
		return status;
	}

	//Generate an asymmetric key pair using the RSA algorithm:
	std::cout << "Generating RSA key pair" << std::endl;
	if (timeCheck)
	{
		auto startKeyGen = std::chrono::steady_clock::now();
		keyGen(hRsaAlg, &hKey, keySize);
		auto endKeyGen = std::chrono::steady_clock::now();
		std::chrono::duration<double> diffKeyGen = endKeyGen - startKeyGen;
		sumKeyGenTime += diffKeyGen.count();
	}
	else
	{
		keyGen(hRsaAlg, &hKey, keySize);
	}
	if (hKey == NULL)
	{
		std::cout << "Invalid key handle" << std::endl;
		return 0;
	}
	std::cout << "Finish Generate RSA key pair" << std::endl;

	//Sign and verify input msg using the RSA key pair:
	std::cout << "Sign/Verify input msg with key" << std::endl;
	if (timeCheck)
	{
		auto startSign = std::chrono::steady_clock::now();
		signMsg1VerifyMsg2(hKey, signHash, input1, input2);
		auto endSign = std::chrono::steady_clock::now();
		std::chrono::duration<double> diffSign = endSign - startSign;
		sumSignTime += diffSign.count();
	}
	else
	{
		signMsg1VerifyMsg2(hKey, signHash, input1, input2);
	}
	std::cout << "Finish Sign/Verify input msg" << std::endl;
	
	//Remove the key handle from memory:
	status = BCryptDestroyKey(hKey);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptDestroyKey with error code 0x%08x\n", status);
		return status;
	}

	//Close the RSA algorithm provider:
	status = BCryptCloseAlgorithmProvider(hRsaAlg, NULL);
	if (!NT_SUCCESS(status))
	{
		wprintf(L"Error: failed in BCryptCloseAlgorithmProvider with error code 0x%08x\n", status);
		return status;
	}

	return 0;
}

/*
* build random hex input in the given length.
*/
void buildHexInput(char str[], int length)
{
	//hexadecimal characters
	char hex_characters[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	for (int i = 0; i < length; i++)
	{
		str[i] = hex_characters[rand() % 16];
	}
	str[length] = 0;
}

/*
* test the performance of Key Gen and Sign operations on a random input.
* call testVerifyKey function with timeCheck == true and 2 references for time counters.
* print the average time of them.
*/
int testPerformance(int keySize, int signHash, int loopsNum)
{
	int inputLen = (signHash == 1) ? 20 : 32;
	char* hexInput = new char[inputLen + 1];
	buildHexInput(hexInput, inputLen);

	double sumKeyGenTime = 0;
	double sumSignTime = 0;

	for (int i = 0; i < loopsNum; i++)
	{
		testVerifyKey(keySize, signHash, hexInput, hexInput, true, sumKeyGenTime, sumSignTime);
	}

	std::cout << "The average time of Key Gen is: " << sumKeyGenTime / loopsNum << " seconds" << std::endl;
	std::cout << "The average time of Sign operations is: " << sumSignTime / loopsNum << " seconds" << std::endl;

	delete[] hexInput;

	return 0;
}

/**
* convert string to int.
*/
int stringToint(char* s, int &num)
{
	char* pEnd = nullptr;
	errno = 0;
	num = (int)strtol(s, &pEnd, 10);
	if ((errno == ERANGE && (num == LONG_MAX || num == LONG_MIN)) || (errno != 0 && num == 0)) 
	{
		perror("strtol");
		return EXIT_FAILURE;
	}
	if (pEnd == s) 
	{
		std::cout << "No digits were found" << std::endl;
		return EXIT_FAILURE;
	}
	return 0;
}

/**
 * to excute the program please enter:
 * 1. RSA key size: 2048 or 4096
 * 2. sign hash options: 1 or 256 (for BCRYPT_SHA1_ALGORITHM or BCRYPT_SHA256_ALGORITHM)
 * if you want to verify: 3. input1 
 *						  4. input2
 * if want to test performance: 3. int number of loops.
 * pay attention that if you choose 1 in sign hash, the inputs length has to be 20,
 * and if you choose 256 in sign hash, the inputs length has to be 32.
 * return 0 for success, 1 otherwise.
 */
int main(int argc, char* argv[])
{
	//At least 3 user's inputs - key size, sign hash, loops number or input1 and input2.
	if (argc < 4)
	{
		std::cout << "Usage: testRSA <2048 or 4096> <1 or 256> <int or <input1> <input2>>" << std::endl;
		return EXIT_FAILURE;
	}

	//too much inputs
	if (argc != 4 && argc != 5)
	{
		std::cout << "Too many arguments, please try again" << std::endl;
		return EXIT_FAILURE;
	}

	int keySize = 0, signHash = 0;
	if (stringToint(argv[1], keySize) > 0)
	{
		return EXIT_FAILURE;
	}
	if (stringToint(argv[2], signHash) > 0)
	{
		return EXIT_FAILURE;
	}

	//Check user's inputs:
	if (keySize != 2048 && keySize != 4096)
	{
		std::cout << "Problem with the RSA key size - suppose to press 2048 or 4096, please try again" << std::endl;
		return EXIT_FAILURE;
	}
	if (signHash != 1 && signHash != 256)
	{
		std::cout << "Problem with the sign hash - suppose to press 1 or 256, please try again" << std::endl;
		return EXIT_FAILURE;
	}

	//Test generates a key, signs input1 and verifies input2
	if (argc == 5)
	{
		int len1 = strlen(argv[3]);
		int len2 = strlen(argv[4]);
		if (signHash == 1 && (len1 != 20 || len2 != 20))
		{
			std::cout << "Problem with the input - if press 1 for sign hash, the inputs' length suppose to be 20, please try again" << std::endl;
			return EXIT_FAILURE;
		}
		if (signHash == 256 && (len1 != 32 || len2 != 32))
		{
			std::cout << "Problem with the input - if press 256 for sign hash, the inputs' length suppose to be 32, please try again" << std::endl;
			return EXIT_FAILURE;
		}
		double val = 0;
		return testVerifyKey(keySize, signHash, argv[3], argv[4], false, val, val);
	}

	//Test performance
	else if (argc == 4)
	{
		int loopsNum = 0;
		if (stringToint(argv[3], loopsNum) > 0)
		{
			return EXIT_FAILURE;
		}
		if (loopsNum < 0)
		{
			std::cout << "Problem with the number of loops - suppose to be positive int, please try again" << std::endl;
			return EXIT_FAILURE;
		}
		return testPerformance(keySize, signHash, loopsNum);
	}
	return EXIT_FAILURE;
}
