#include <windows.h>
#include <iostream>
#include <bcrypt.h>
#include <chrono>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

//input1 = "Hello World!":
static const BYTE input1[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                              0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };
//input2 = "Have a nice day":
static const BYTE input2[] = { 0x48, 0x61, 0x76, 0x65, 0x20, 0x61, 0x20, 0x6e,
                              0x69, 0x63, 0x65, 0x20, 0x64, 0x61, 0x79 };


void printFromMemory(void* Mem, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        //wprintf -> writes the wide string pointed to by format to stdout.
        //L -> For floating point types, causes printf to expect a long double argument.
        wprintf(L"0x%02x, ", ((unsigned char*)Mem)[i]);
        if ((i + 1) % 10 == 0)
        {
            putchar('\n');
        }
    }
    std::cout << std::endl;
}


void testSignVerify(ULONG key_size, LPCWSTR sign_hash)
{
    BCRYPT_ALG_HANDLE phAlgorithm = NULL, phHashAlg = NULL, phSignAlg = NULL;
    BCRYPT_KEY_HANDLE phKey = NULL, phTmpKey = NULL;
    BCRYPT_HASH_HANDLE phHash = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL, status2 = STATUS_UNSUCCESSFUL;
    PBYTE pbHashObject = NULL, pbHash = NULL, pbSignature = NULL, pbBlob = NULL;
    DWORD cbData = 0, cbHashObject = 0, cbHash = 0, cbSignature = 0;
    ULONG pcbBlob = 0;

    //===============================generate key pair:===============================

    status = BCryptOpenAlgorithmProvider(&phAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!(NT_SUCCESS(status)))
    {
        wprintf(L"ERROR: failed in algorithm provider - status 0x%x\n", status);
        goto Cleanup;
    }

    /** ULONG dwLength = BCRYPT_RSA_ALGORITHM, key size must be greater than or equal to 512 bits,
     * less than or equal to 16384 bits, and must be a multiple of 64. */
    status = BCryptGenerateKeyPair(phAlgorithm, &phKey, key_size, 0);
    if (!(NT_SUCCESS(status)))
    {
        wprintf(L"ERROR: failed in generate key pair - status 0x%x\n", status);
        goto Cleanup;
    }

    status = BCryptSetProperty(phAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!(NT_SUCCESS(status)))
    {
        wprintf(L"ERROR: failed in set property - status 0x%x\n", status);
        goto Cleanup;
    }

    status = BCryptFinalizeKeyPair(phKey, 0);
    if (!(NT_SUCCESS(status)))
    {
        wprintf(L"ERROR: failed in finalizer key pair - status 0x%x\n", status);
        goto Cleanup;
    }

    //===============================sign message:===============================

    //algorithm handle:
    status2 = BCryptOpenAlgorithmProvider(&phHashAlg, sign_hash, NULL, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in algorithm provider - status 0x%x\n", status2);
        goto Cleanup;
    }

    //sign handle:
    status2 = BCryptOpenAlgorithmProvider(&phSignAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in algorithm provider - status 0x%x\n", status2);
        goto Cleanup;
    }

    //calculate the buffer size of the hash table:
    status2 = BCryptGetProperty(phHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in BCryptGetProperty - status 0x%x\n", status2);
        goto Cleanup;
    }

    //memory allocation to the hash object:
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (pbHashObject == NULL)
    {
        wprintf(L"ERROR: failed in memory allocation\n");
        goto Cleanup;
    }

    //get the hash length:
    status2 = BCryptGetProperty(phHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in BCryptGetProperty - status 0x%x\n", status2);
        goto Cleanup;
    }

    //memory allocation to the hash buffer:
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (pbHash == NULL)
    {
        wprintf(L"ERROR: failed in memory allocation\n");
        goto Cleanup;
    }

    //create hash table:
    status2 = BCryptCreateHash(phHashAlg, &phHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in create hash table - status 0x%x\n", status2);
        goto Cleanup;
    }

    //hash input1:
    status2 = BCryptHashData(phHash, (PBYTE)input1, sizeof(input1), 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in hash input1 - status 0x%x\n", status2);
        goto Cleanup;
    }

    //closing the hash:
    status2 = BCryptFinishHash(phHash, pbHash, cbHash, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in closing the hash - status 0x%x\n", status2);
        goto Cleanup;
    }

    std::cout << "sign input1 with hash:" << std::endl;
    printFromMemory(pbHash, cbHash);

    //now we use the key from the generate key pair step - BCryptFinalizeKeyPair - and go back to status:
    //signing the hash:
    status = BCryptSignHash(phKey, NULL, pbHash, cbHash, NULL, 0, &cbSignature, 0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"ERROR: failed in signing the hash - status 0x%x\n", status);
        goto Cleanup;
    }

    //memory allocation to the signature buffer:
    pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
    if (pbSignature == NULL)
    {
        wprintf(L"ERROR: failed in memory allocation\n");
        goto Cleanup;
    }

    //combine the data and signature into a message:
    status = BCryptSignHash(phKey, NULL, pbHash, cbHash, pbSignature, cbSignature, &cbSignature, 0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"ERROR: failed in signing the hash - status 0x%x\n", status);
        goto Cleanup;
    }

    std::cout << "the signature is:" << std::endl;
    printFromMemory(pbSignature, cbSignature);

    //===============================verify the signature:===============================

    //obtain the public portion of the asymmetric key pair that was used to sign the hash:
    status = BCryptExportKey(phKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &pcbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"ERROR: failed in export key - status 0x%x\n", status);
        goto Cleanup;
    }

    //memory allocation to key BLOB buffer:
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pcbBlob);
    if (pbBlob == NULL)
    {
        wprintf(L"ERROR: failed in memory allocation\n");
        goto Cleanup;
    }

    //save ephemeral key to a key BLOB:
    status = BCryptExportKey(phKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbBlob, pcbBlob, &pcbBlob, 0);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"ERROR: failed in export key - status 0x%x\n", status);
        goto Cleanup;
    }

    //pass this key BLOB to BCryptImportKeyPair:
    status2 = BCryptImportKeyPair(phSignAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &phTmpKey, pbBlob, pcbBlob, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in import key pair - status 0x%x\n", status2);
        goto Cleanup;
    }

    //verify the signature:
    status2 = BCryptVerifySignature(phTmpKey, NULL, pbHash, cbHash, pbSignature, cbSignature, 0);
    if (!NT_SUCCESS(status2))
    {
        wprintf(L"ERROR: failed in verify signature - status 0x%x\n", status2);
        goto Cleanup;
    }

    std::cout << "verify signature:" << std::endl;
    printFromMemory(pbSignature, cbSignature);

    //===============================Cleanup:===============================
    Cleanup:
    if (phAlgorithm)
    {
        BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    }
    if (phKey)
    {
        BCryptDestroyKey(phKey);
    }
    if (phHashAlg)
    {
        BCryptCloseAlgorithmProvider(phHashAlg, 0);
    }
    if (phSignAlg)
    {
        BCryptCloseAlgorithmProvider(phSignAlg, 0);
    }
    if (phHash)
    {
        BCryptDestroyHash(phHash);
    }
    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }
    if (pbHash)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }
    if (pbSignature)
    {
        HeapFree(GetProcessHeap(), 0, pbSignature);
    }
    if (pbBlob)
    {
        HeapFree(GetProcessHeap(), 0, pbBlob);
    }
    if (phTmpKey)
    {
        BCryptDestroyKey(phTmpKey);
    }
}


int main()
{
    //RSA key size: 2048, 4096
    ULONG key_size = 2048;

    //sign hash options: BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM
    LPCWSTR sign_hash = BCRYPT_SHA1_ALGORITHM;

    //choose how many loops:
    int num = 1;
    auto sum = 0;
    for (int i = 0; i < num; i++)
    {
        auto start = std::chrono::steady_clock::now();
        testSignVerify(key_size, sign_hash);
        auto end = std::chrono::steady_clock::now();
        auto diff = end - start;
        sum += (diff).count();
    }

    std::cout << "the average time of hey gen and sign operations is " << sum / num << " ms" << std::endl;

    return 0;
}
