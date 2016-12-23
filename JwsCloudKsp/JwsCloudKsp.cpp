/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"

#import "CloudKspLibMg.tlb" raw_interfaces_only
using namespace CloudKspLibMg;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)                  (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER            ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED                ((NTSTATUS)0xC00000BBL)
#endif

#define SN_KSP_PROVIDER_NAME				L"JW Secure Cloud Key Storage Provider"
#define DEFAULT_KEY_LENGTH					2048

//
// Hash size helper definitions
//

#define cbMD5                               16
#define cbSHA1                              20
#define cbSHA256                            32
#define cbSHA384                            48
#define cbSHA512                            64
#define cbSHAMD5                            36

//
// Flow macros
// 

void
WINAPI
_OutputDbgStrKsp(
    __in  LPSTR szFile,
    __in  DWORD dwLine,
    __in  LPSTR szMsg,
    __in_opt LPWSTR wszDetail,
    __in  DWORD dwStatus)
{
    CHAR rgsz[600];
    LPSTR szTag = "INFO";

    if (0 != dwStatus)
        szTag = "ERROR";

    if (wszDetail == NULL)
    {
        StringCbPrintfA(
            rgsz,
            sizeof(rgsz),
            "%s: %s - 0x%x, file %s, line %d\n",
            szTag,
            szMsg,
            dwStatus,
            szFile,
            dwLine);
    }
    else
    {
        StringCbPrintfA(
            rgsz,
            sizeof(rgsz),
            "%s: %s (%S) - 0x%x, file %s, line %d\n",
            szTag,
            szMsg,
            wszDetail,
            dwStatus,
            szFile,
            dwLine);
    }

    OutputDebugStringA(rgsz);
}

#define CHECK_BOOL(_X) {                                        \
if (FALSE == (_X)) {                                            \
    status = GetLastError();                                    \
    _OutputDbgStrKsp(__FILE__, __LINE__, #_X, NULL, status);       \
    goto Cleanup;                                               \
}                                                               \
}

#define CHECK_STATUS(_X) {                                      \
if (0 != (status = _X)) {										\
    _OutputDbgStrKsp(__FILE__, __LINE__, #_X, NULL, status);       \
    goto Cleanup;                                               \
}                                                               \
}

#define CHECK_COM(_X) {                                         \
if (FALSE == SUCCEEDED(status = (DWORD) _X)) {                  \
    _OutputDbgStrKsp(__FILE__, __LINE__, #_X, NULL, status);    \
    goto Cleanup;                                               \
}                                                               \
}

#define CHECK_ALLOC(_X) {                                       \
if (NULL == (_X)) {                                             \
    status = NTE_NO_MEMORY;                                     \
    goto Cleanup;                                               \
}                                                               \
}

#define LOG_CALL(_X, _Y) {                                      \
    _OutputDbgStrKsp(__FILE__, __LINE__, #_X, NULL, _Y); }

#define LOG_CALL2(_X, _Z, _Y) {                                 \
    _OutputDbgStrKsp(__FILE__, __LINE__, #_X, _Z, _Y); }

//
//  Properties (key and providers)
//  key property        - supports 3 defined ones - KEY_USAGE_PROPERTY, Max Name Length Property, Max Data length Property  
//  provider property   - supports 3 defined ones - supported algorithms for this provider, Max Name Length Property, Max Data length Property  
//
//#define KEY_SUPPORTED_ALGORITHM_PROPERTY       L"Supported Key Algorithm"
#define PROV_SUPPORTED_ALGORITHMS_PROPERTY     L"Supported Provider Algorithm"
#define MAX_NAME_LENGTH_PROPERTY               L"Max Property Name Length"
#define MAX_DATA_LENGTH_PROPERTY               L"Max Property Data Length"

// Maximum length of property name (in characters)
DWORD const MAX_PROPERTY_NAME_LENGTH = 64;

// Maximum length of property data (in bytes)
#define MAX_DATA_LENGTH                        0x100000

typedef unsigned int ALG_ID;

//
//      typedef ULONG_PTR HCRYPTKEY;
//      typedef unsigned int ALG_ID;
//
typedef struct _SN_KSP_KEY {
    NCRYPT_KEY_HANDLE hKey;
    LPWSTR wszAlgorithmName;
    LPWSTR wszKeyName;
    DWORD dwFlags;
    DWORD dwStrongnetKeyFlags;
} SN_KSP_KEY, *PSN_KSP_KEY;

typedef struct _SN_KSP_PROVIDER {
    NCRYPT_PROV_HANDLE hProv;
    LPWSTR wszAuthClientId;
    LPWSTR wszAuthClientSecret;
    LPWSTR wszVaultAddress;
    ICloudKspPtr pCloudKsp;
} SN_KSP_PROVIDER, *PSN_KSP_PROVIDER;

void *
MALLOC(size_t cb)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
}

void
FREE(LPVOID p)
{
    HeapFree(GetProcessHeap(), 0, p);
}

//
// Helper for populating the key structure
//
SECURITY_STATUS
WINAPI
_CreateKeyContext(
    __out           PSN_KSP_KEY *ppKey,
    __in            LPWSTR wszKeyName,
    __in            DWORD dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;

    //
    // Create the structure
    //

    CHECK_ALLOC(*ppKey = (PSN_KSP_KEY)MALLOC(sizeof(SN_KSP_KEY)));

    //
    // Set the algorithm
    //

    CHECK_ALLOC((*ppKey)->wszAlgorithmName = (LPWSTR)MALLOC(
        sizeof(WCHAR) * (1 + wcslen(BCRYPT_RSA_ALGORITHM))));
    StringCchCopy(
        (*ppKey)->wszAlgorithmName,
        1 + wcslen(BCRYPT_RSA_ALGORITHM),
        BCRYPT_RSA_ALGORITHM);

    //
    // Key name
    //

    if (NULL != wszKeyName)
    {
        CHECK_ALLOC((*ppKey)->wszKeyName = (LPWSTR)MALLOC(
            sizeof(WCHAR) * (1 + wcslen(wszKeyName))));
        StringCchCopy(
            (*ppKey)->wszKeyName,
            1 + wcslen(wszKeyName),
            wszKeyName);
    }

    //
    // Flags
    //

    (*ppKey)->dwFlags = dwFlags;

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI
_OpenEncodedPublicKey(
    __in        PSN_KSP_PROVIDER pProv,
    __in        LPWSTR wszPublicModulusB64,
    __inout     PSN_KSP_KEY pKey)
{
    SECURITY_STATUS status = 0;
    PBYTE pbModulus = NULL;
    DWORD cbModulus = 0;
    BCRYPT_RSAKEY_BLOB *pKeyBlob = NULL;
    BYTE rgbPublicExponent[] = { 0x01, 0x00, 0x01 };

    //
    // Decode the modulus
    //

    CHECK_BOOL(CryptStringToBinaryW(
        wszPublicModulusB64,
        0,
        CRYPT_STRING_BASE64,
        NULL,
        &cbModulus,
        NULL,
        NULL));

    CHECK_ALLOC(pbModulus = (PBYTE)MALLOC(cbModulus));

    CHECK_BOOL(CryptStringToBinaryW(
        wszPublicModulusB64,
        0,
        CRYPT_STRING_BASE64,
        pbModulus,
        &cbModulus,
        NULL,
        NULL));

    //
    // Build a key blob
    //

    CHECK_ALLOC(pKeyBlob = (BCRYPT_RSAKEY_BLOB *)MALLOC(
        sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rgbPublicExponent) + cbModulus));
    pKeyBlob->cbModulus = cbModulus;
    pKeyBlob->cbPublicExp = sizeof(rgbPublicExponent);
    pKeyBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pKeyBlob->BitLength = cbModulus * 8;
    memcpy(
        ((PBYTE)pKeyBlob) + sizeof(BCRYPT_RSAKEY_BLOB),
        rgbPublicExponent,
        sizeof(rgbPublicExponent));
    memcpy(
        ((PBYTE)pKeyBlob) + sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rgbPublicExponent),
        pbModulus,
        cbModulus);

    //
    // Import the helper key
    //

    CHECK_STATUS(NCryptImportKey(
        pProv->hProv,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        &pKey->hKey,
        (PBYTE)pKeyBlob,
        sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rgbPublicExponent) + cbModulus,
        0));

Cleanup:
    if (NULL != pbModulus)
        FREE(pbModulus);
    return status;
}

SECURITY_STATUS
WINAPI
_OpenWrappedProvider(
    __inout PSN_KSP_PROVIDER pProv)
{
    SECURITY_STATUS status = ERROR_SUCCESS;

    if (NULL == pProv->hProv)
    {
        CHECK_STATUS(NCryptOpenStorageProvider(
            &pProv->hProv,
            MS_KEY_STORAGE_PROVIDER,
            0));
    }

Cleanup:
    return status;
}

/**********************************************************************************/
/* KSP Interface Implementation                                                   */
/**********************************************************************************/

SECURITY_STATUS
WINAPI KspOpenStorageProvider(
    __out   NCRYPT_PROV_HANDLE * pProvider,
    __in    LPCWSTR wszProviderName,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS  status = S_OK;
    SN_KSP_PROVIDER  *pKspProvider = NULL;
    ICloudKspPtr pCloudKsp(__uuidof(AzureKspLib));
    
    UNREFERENCED_PARAMETER(wszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
    
    //
    // Allocate memory for the provider context structure
    //

    CHECK_ALLOC(pKspProvider = (SN_KSP_PROVIDER *)MALLOC(
        sizeof(SN_KSP_PROVIDER)));

    //
    // Shim as many calls as possible
    //

    CHECK_STATUS(_OpenWrappedProvider(pKspProvider));

    //
    // Set the vault parameters
    //

    // TODO
    pKspProvider->wszAuthClientId = L"xxx";
    pKspProvider->wszAuthClientSecret = L"yyy";
    pKspProvider->wszVaultAddress = L"zzz";

    // 
    // Initialize the COM layer
    //

    pKspProvider->pCloudKsp = pCloudKsp;
    pKspProvider->pCloudKsp->AddRef();

    //
    // Output the new context
    //

    *pProvider = (NCRYPT_PROV_HANDLE)pKspProvider;
    pKspProvider = NULL;

Cleanup:
    if (NULL != pKspProvider)
        FREE(pKspProvider);
    LOG_CALL(KspOpenStorageProvider, status);
    return status;
}

SECURITY_STATUS
WINAPI KspCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR wszAlgId,
    __in_opt LPCWSTR wszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = NULL;

    //
    // Allocate key context memory
    //

    CHECK_STATUS(_CreateKeyContext(&pKey, (LPWSTR)wszKeyName, dwFlags));

    //
    // Output the new key context
    //

    *phKey = (NCRYPT_KEY_HANDLE)pKey;

Cleanup:
    LOG_CALL(KspCreatePersistedKey, status);
    return status;
}

SECURITY_STATUS
WINAPI KspFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    LPWSTR wszPublicModulusB64 = NULL;

    //
    // Create a new key
    //

    CHECK_COM(pProv->pCloudKsp->CreateKey(
        pProv->wszAuthClientId,
        pProv->wszAuthClientSecret,
        pProv->wszVaultAddress,
        pKey->wszKeyName,
        &wszPublicModulusB64));

    //
    // Import the public
    //

    CHECK_STATUS(_OpenEncodedPublicKey(
        pProv, wszPublicModulusB64, pKey));

Cleanup:
    if (NULL != wszPublicModulusB64)
        CoTaskMemFree(wszPublicModulusB64);
    LOG_CALL(KspFinalizeKey, status);
    return status;
}

SECURITY_STATUS
WINAPI KspOpenKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR wszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = NULL;
    WCHAR rgwszMessage[MAX_PATH];
    LPWSTR wszPublicModulusB64 = NULL;

    CHECK_STATUS(_CreateKeyContext(&pKey, (LPWSTR)wszKeyName, dwFlags));

    CHECK_STATUS(_OpenWrappedProvider(pProv));

    //
    // Read the public key from the cloud
    //

    CHECK_COM(pProv->pCloudKsp->GetKey(
        pProv->wszAuthClientId,
        pProv->wszAuthClientSecret,
        pProv->wszVaultAddress,
        pKey->wszKeyName,
        &wszPublicModulusB64));

    //
    // Decode and import
    //

    CHECK_STATUS(_OpenEncodedPublicKey(pProv, wszPublicModulusB64, pKey));

    //
    // On success, return a valid key handle
    //

    *phKey = (NCRYPT_KEY_HANDLE)pKey;

Cleanup:

    StringCbPrintfW(
        rgwszMessage,
        sizeof(rgwszMessage),
        L"%s %d 0x%x",
        wszKeyName,
        dwLegacyKeySpec,
        dwFlags);
    if (NULL != wszPublicModulusB64)
        CoTaskMemFree(wszPublicModulusB64);
    LOG_CALL2(KspOpenKey, rgwszMessage, status);
    return status;
}

SECURITY_STATUS
WINAPI KspEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_opt(cbOutput) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;

    status = NCryptEncrypt(
        pKey->hKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);

    LOG_CALL(KspEncrypt, status);
    return status;
}

SECURITY_STATUS
WINAPI KspDecrypt(
    __in        NCRYPT_PROV_HANDLE hProvider,
    __in        NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in        DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_opt(cbOutput) PBYTE pbOutput,
    __in        DWORD   cbOutput,
    __out       DWORD * pcbResult,
    __in        DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    LPWSTR wszEncryptedB64 = NULL;
    DWORD cchEncryptedB64 = 0;
    LPWSTR wszDecryptedB64 = NULL;

    //
    // Encode the ciphertext
    //

    CHECK_BOOL(CryptBinaryToStringW(
        pbInput,
        cbInput,
        CRYPT_STRING_BASE64,
        NULL,
        &cchEncryptedB64));

    CHECK_ALLOC(wszEncryptedB64 = (LPWSTR)MALLOC(sizeof(WCHAR) * cchEncryptedB64));

    CHECK_BOOL(CryptBinaryToStringW(
        pbInput,
        cbInput,
        CRYPT_STRING_BASE64,
        wszEncryptedB64,
        &cchEncryptedB64));

    //
    // Decrypt using the cloud key
    //

    CHECK_COM(pProv->pCloudKsp->Decrypt(
        wszEncryptedB64,
        &wszDecryptedB64));

    //
    // Decode the result
    //

    *pcbResult = cbOutput;
    if (FALSE == CryptStringToBinaryW(
        wszDecryptedB64,
        0,
        CRYPT_STRING_BASE64,
        pbOutput,
        pcbResult,
        NULL,
        NULL))
    {
        if (ERROR_MORE_DATA == (status = GetLastError()))
        {
            status = ERROR_INSUFFICIENT_BUFFER;
        }
    }

Cleanup:
    if (NULL != wszEncryptedB64)
        FREE(wszEncryptedB64);
    if (NULL != wszDecryptedB64)
        CoTaskMemFree(wszDecryptedB64);
    LOG_CALL(KspDecrypt, status);
    return status;
}

SECURITY_STATUS
WINAPI KspSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_opt(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    LPWSTR wszDigestB64 = NULL;
    DWORD cchDigestB64 = 0;
    LPWSTR wszSignatureB64 = NULL;

    //
    // Encode the hash
    //

    CHECK_BOOL(CryptBinaryToStringW(
        pbHashValue,
        cbHashValue,
        CRYPT_STRING_BASE64,
        NULL,
        &cchDigestB64));

    CHECK_ALLOC(wszDigestB64 = (LPWSTR)MALLOC(sizeof(WCHAR) * cchDigestB64));

    CHECK_BOOL(CryptBinaryToStringW(
        pbHashValue,
        cbHashValue,
        CRYPT_STRING_BASE64,
        wszDigestB64,
        &cchDigestB64));

    //
    // Sign the hash using the cloud key
    //

    CHECK_COM(pProv->pCloudKsp->Sign(
        wszDigestB64,
        &wszSignatureB64));

    //
    // Decode the signature
    //

    *pcbResult = cbSignature;
    if (FALSE == CryptStringToBinaryW(
        wszSignatureB64,
        0,
        CRYPT_STRING_BASE64,
        pbSignature,
        pcbResult,
        NULL,
        NULL))
    {
        if (ERROR_MORE_DATA == (status = GetLastError()))
        {
            status = ERROR_INSUFFICIENT_BUFFER;
        }
    }

Cleanup:
    if (NULL != wszDigestB64)
        FREE(wszDigestB64);
    if (NULL != wszSignatureB64)
        CoTaskMemFree(wszSignatureB64);
    LOG_CALL(KspSignHash, status);
    return status;
}

SECURITY_STATUS
WINAPI KspVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;

    CHECK_STATUS(NCryptVerifySignature(
        pKey->hKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,                             // key to be exported
    __in_opt NCRYPT_KEY_HANDLE hExportKey,                      // key for encryption
    __in    LPCWSTR wszBlobType,                                // key blob type
    __in_opt NCryptBufferDesc *pParameterList,                  // NULL 
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput, // output bytes
    __in    DWORD   cbOutput,                                   // bytes exported
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    PSN_KSP_KEY pExportKey = (PSN_KSP_KEY)hExportKey;

    CHECK_STATUS(NCryptExportKey(
        pKey->hKey,
        NULL != hExportKey ? pExportKey->hKey : NULL,
        wszBlobType,
        pParameterList,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,          // import key - ignored 
    __in    LPCWSTR wszBlobType,                    // blob type
    __in_opt NCryptBufferDesc *pParameterList,      //            - ignored
    __out   NCRYPT_KEY_HANDLE *phKey,               // out key
    __in_bcount(cbData) PBYTE pbData,               // bytes imported
    __in    DWORD   cbData,                         // length imported
    __in    DWORD   dwFlags)                        // flags
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_KEY pNewKey = NULL;
    PSN_KSP_KEY pImportKey = (PSN_KSP_KEY)hImportKey;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    CHECK_ALLOC(pNewKey = (PSN_KSP_KEY)MALLOC(sizeof(SN_KSP_KEY)));

    status = NCryptImportKey(
        pProv->hProv,
        NULL != pImportKey ? pImportKey->hKey : NULL,
        wszBlobType,
        pParameterList,
        &pNewKey->hKey,
        pbData,
        cbData,
        dwFlags);

    *phKey = (NCRYPT_KEY_HANDLE)pNewKey;

Cleanup:
    LOG_CALL(KspImportKey, status);
    return status;
}

SECURITY_STATUS
WINAPI KspIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR wszAlgId,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    CHECK_STATUS(NCryptIsAlgSupported(
        pProv->hProv, wszAlgId, dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR wszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;

    //
    // Filter selected property requests
    //

    if (0 == wcscmp(NCRYPT_KEY_USAGE_PROPERTY, wszProperty))
    {
        // Allow all usages, or Windows certificate enrollment will fail
    }
    else if (0 == wcscmp(NCRYPT_LENGTH_PROPERTY, wszProperty))
    {
        if (2048 != *((DWORD *)pbInput))
        {
            status = NTE_NOT_SUPPORTED;
            goto Cleanup;
        }
    }
    else if (0 == wcscmp(NCRYPT_UI_POLICY_PROPERTY, wszProperty))
    {
        // Allow UI policy for Windows certificate enrollment, even though
        // the KSP currently has no UI
    }
    else if (0 == wcscmp(NCRYPT_EXPORT_POLICY_PROPERTY, wszProperty))
    {
        if (0 != *((DWORD *)pbInput))
        {
            status = NTE_NOT_SUPPORTED;
            goto Cleanup;
        }
    }
    else if (0 == wcscmp(NCRYPT_USE_CONTEXT_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_PIN_PROPERTY, wszProperty))
    {
        // Allow Use Context for certificate enrollment, even though the 
        // provider doesn't use it

        // Allow HWND Handle for TLS, even though the provider doesn't use it

        // Swallow any PIN
    }
    else if (0 == wcscmp(NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_CERTIFICATE_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_SECURITY_DESCR_PROPERTY, wszProperty))
    {
        // Pass these through if there's a wrapped key handle. 
        if (NULL != pKey->hKey)
        {
            CHECK_STATUS(NCryptSetProperty(
                pKey->hKey,
                wszProperty,
                pbInput,
                cbInput,
                dwFlags));
        }
    }
    else
    {
        status = NTE_NOT_SUPPORTED;
        goto Cleanup;
    }

Cleanup:

    LOG_CALL2(KspSetKeyProperty, (LPWSTR)wszProperty, status);
    return status;
}

SECURITY_STATUS
WINAPI KspSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR wszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    //
    // Filter selected property requests
    //

    if (0 == wcscmp(NCRYPT_USE_CONTEXT_PROPERTY, wszProperty))
    {
        // Allow Use Context for certificate enrollment, even though the 
        // provider doesn't use it
    }
    else if (0 == wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, wszProperty))
    {
        // Allow HWND Handle for TLS, even though the provider doesn't use it
    }
    else
    {
        status = NTE_NOT_SUPPORTED;
        goto Cleanup;
    }

Cleanup:
    LOG_CALL2(KspSetProviderProperty, (LPWSTR)wszProperty, status);
    return status;
}

SECURITY_STATUS
WINAPI KspGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR wszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;

    //
    // Filter selected property requests
    //

    if (0 == wcscmp(NCRYPT_LENGTHS_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(NCRYPT_SUPPORTED_LENGTHS);
        if (cbOutput < sizeof(NCRYPT_SUPPORTED_LENGTHS))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        ((NCRYPT_SUPPORTED_LENGTHS *)pbOutput)->dwDefaultLength = 2048;
        ((NCRYPT_SUPPORTED_LENGTHS *)pbOutput)->dwIncrement = 0;
        ((NCRYPT_SUPPORTED_LENGTHS *)pbOutput)->dwMaxLength = 2048;
        ((NCRYPT_SUPPORTED_LENGTHS *)pbOutput)->dwMinLength = 2048;
    }
    else if (0 == wcscmp(NCRYPT_LENGTH_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(DWORD);
        if (cbOutput < sizeof(DWORD))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        *((DWORD *)pbOutput) = 2048;
    }
    else if (0 == wcscmp(NCRYPT_UI_POLICY_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(NCRYPT_UI_POLICY);
        if (cbOutput < sizeof(NCRYPT_UI_POLICY))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        ((NCRYPT_UI_POLICY *)pbOutput)->dwVersion = 1;
        ((NCRYPT_UI_POLICY *)pbOutput)->dwFlags = 0;
        ((NCRYPT_UI_POLICY *)pbOutput)->pszCreationTitle = NULL;
        ((NCRYPT_UI_POLICY *)pbOutput)->pszDescription = NULL;
        ((NCRYPT_UI_POLICY *)pbOutput)->pszFriendlyName = NULL;
    }
    else if (0 == wcscmp(NCRYPT_EXPORT_POLICY_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(DWORD);
        if (cbOutput < sizeof(DWORD))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        *((DWORD *)pbOutput) = 0;
    }
    else if (0 == wcscmp(NCRYPT_KEY_USAGE_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(DWORD);
        if (cbOutput < sizeof(DWORD))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        *((DWORD *)pbOutput) = NCRYPT_ALLOW_ALL_USAGES;
    }
    else if (0 == wcscmp(NCRYPT_USE_CONTEXT_PROPERTY, wszProperty))
    {
        *pcbResult = 0;
    }
    else if (0 == wcscmp(L"CLR IsEphemeral", wszProperty))
    {
        *pcbResult = sizeof(BOOL);
        if (cbOutput < sizeof(BOOL))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        *((BOOL *)pbOutput) = FALSE;
    }
    else if (0 == wcscmp(NCRYPT_NAME_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_UNIQUE_NAME_PROPERTY, wszProperty))
    {
        if (NULL == pKey->wszKeyName)
        {
            *pcbResult = 0;
            goto Cleanup;
        }

        *pcbResult = (DWORD)(sizeof(WCHAR) * (1 + wcslen(pKey->wszKeyName)));
        if (cbOutput < *pcbResult)
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }

        StringCbCopy((LPWSTR)pbOutput, cbOutput, pKey->wszKeyName);
    }
    else if (0 == wcscmp(NCRYPT_SECURITY_DESCR_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_CERTIFICATE_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_ALGORITHM_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_ALGORITHM_GROUP_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, wszProperty) ||
        0 == wcscmp(NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, wszProperty))
    {
        CHECK_STATUS(NCryptGetProperty(
            pKey->hKey,
            wszProperty,
            pbOutput,
            cbOutput,
            pcbResult,
            dwFlags));
    }
    else
    {
        status = NTE_NOT_SUPPORTED;
        goto Cleanup;
    }

Cleanup:

    LOG_CALL2(KspGetKeyProperty, (LPWSTR)wszProperty, status);
    return status;
}

SECURITY_STATUS
WINAPI KspGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR wszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    //
    // Filter selected property requests
    //

    if (0 == wcscmp(NCRYPT_VERSION_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(DWORD);
        if (cbOutput < sizeof(DWORD))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }
        *((DWORD *)pbOutput) = 1;
    }
    else if (0 == wcscmp(NCRYPT_NAME_PROPERTY, wszProperty))
    {
        *pcbResult =
            (DWORD)(sizeof(WCHAR) * (1 + wcslen(SN_KSP_PROVIDER_NAME)));
        if (cbOutput < *pcbResult)
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }
        StringCbCopy((LPWSTR)pbOutput, cbOutput, SN_KSP_PROVIDER_NAME);
    }
    else if (0 == wcscmp(NCRYPT_IMPL_TYPE_PROPERTY, wszProperty))
    {
        *pcbResult = sizeof(DWORD);
        if (cbOutput < sizeof(DWORD))
        {
            if (NULL != pbOutput)
            {
                status = ERROR_INSUFFICIENT_BUFFER;
            }
            goto Cleanup;
        }
        *((DWORD *)pbOutput) = NCRYPT_IMPL_HARDWARE_FLAG;
    }
    else if (0 == wcscmp(NCRYPT_MAX_NAME_LENGTH_PROPERTY, wszProperty))
    {
        CHECK_STATUS(_OpenWrappedProvider(pProv));
        CHECK_STATUS(NCryptGetProperty(
            pProv->hProv,
            wszProperty,
            pbOutput,
            cbOutput,
            pcbResult,
            dwFlags));
    }
    else
    {
        status = NTE_NOT_SUPPORTED;
        goto Cleanup;
    }

Cleanup:
    LOG_CALL2(KspGetProviderProperty, (LPWSTR)wszProperty, status);
    return status;
}

SECURITY_STATUS
WINAPI KspFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;

    if (pKey->hKey)
        NCryptFreeObject(pKey->hKey);
    if (pKey->wszKeyName)
        FREE(pKey->wszKeyName);
    if (pKey->wszAlgorithmName)
        FREE(pKey->wszAlgorithmName);

    FREE(pKey);
    return 0;
}

//
//  Delete key and key file 
//
SECURITY_STATUS
WINAPI KspDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    LOG_CALL(KspDeleteKey, status);
    return status;
}

SECURITY_STATUS
WINAPI KspFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    if (NULL != pProv->pCloudKsp)
        pProv->pCloudKsp->Release();
    if (NULL != pProv->hProv)
        NCryptFreeObject(pProv->hProv);
    FREE(pProv);
    LOG_CALL(KspFreeProvider, 0);
    return 0;
}

SECURITY_STATUS
WINAPI KspFreeBuffer(
    __deref PVOID   pvInput)
{
    FREE(pvInput);
    return ERROR_SUCCESS;
}

SECURITY_STATUS
WINAPI KspFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    UNREFERENCED_PARAMETER(hProvider);
    FREE((PVOID)hSharedSecret);
    LOG_CALL(KspFreeSecret, ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

SECURITY_STATUS
WINAPI KspDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in        NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    CHECK_STATUS(NCryptDeriveKey(
        hSharedSecret,
        pwszKDF,
        pParameterList,
        pbDerivedKey,
        cbDerivedKey,
        pcbResult,
        dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations,
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    //
    // Count the algorithms supported for cloud keys
    //

    *pdwAlgCount = 0;
    if (NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION & dwAlgOperations ||
        0 == dwAlgOperations)
    {
        *pdwAlgCount += 1;
    }
    if (NCRYPT_SIGNATURE_OPERATION & dwAlgOperations ||
        0 == dwAlgOperations)
    {
        *pdwAlgCount += 1;
    }

    //
    // Allocate the structure
    //

    CHECK_ALLOC(*ppAlgList = (NCryptAlgorithmName *)MALLOC(
        *pdwAlgCount * sizeof(NCryptAlgorithmName)));

    //
    // Fill in the structure
    //

    *pdwAlgCount = 0;
    if (NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION & dwAlgOperations ||
        0 == dwAlgOperations)
    {
        (*ppAlgList)[*pdwAlgCount].dwAlgOperations =
            NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
            BCRYPT_SIGNATURE_OPERATION;
        (*ppAlgList)[*pdwAlgCount].dwClass =
            NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
        (*ppAlgList)[*pdwAlgCount].pszName = NCRYPT_RSA_ALGORITHM;
        *pdwAlgCount += 1;
    }
    if (NCRYPT_SIGNATURE_OPERATION & dwAlgOperations ||
        0 == dwAlgOperations)
    {
        (*ppAlgList)[*pdwAlgCount].dwAlgOperations =
            NCRYPT_SIGNATURE_OPERATION;
        (*ppAlgList)[*pdwAlgCount].dwClass = NCRYPT_SIGNATURE_INTERFACE;
        (*ppAlgList)[*pdwAlgCount].pszName = NCRYPT_RSA_SIGN_ALGORITHM;
        *pdwAlgCount += 1;
    }

Cleanup:
    LOG_CALL(KspEnumAlgorithms, status);
    return status;
}

SECURITY_STATUS
WINAPI KspEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR wszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    CHECK_STATUS(NCryptEnumKeys(
        pProv->hProv,
        wszScope,
        ppKeyName,
        ppEnumState,
        dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;

    CHECK_STATUS(NCryptNotifyChangeKey(
        pProv->hProv, phEvent, dwFlags));

Cleanup:
    return status;
}

SECURITY_STATUS
WINAPI KspPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR wszOperation,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PSN_KSP_PROVIDER pProv = (PSN_KSP_PROVIDER)hProvider;
    PSN_KSP_KEY pKey = (PSN_KSP_KEY)hKey;
    
    status = (DWORD)NTE_NOT_SUPPORTED;
    
Cleanup:
    LOG_CALL(KspPromptUser, status);
    return status;
}

SECURITY_STATUS
WINAPI KspSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE* phSharedSecret,
    __in    DWORD   dwFlags)
{
    DWORD status = 0;
    PSN_KSP_KEY pPriv = (PSN_KSP_KEY)hPrivKey;
    PSN_KSP_KEY pPub = (PSN_KSP_KEY)hPubKey;

    CHECK_STATUS(NCryptSecretAgreement(
        pPriv->hKey,
        pPub->hKey,
        phSharedSecret,
        dwFlags));

Cleanup:
    return status;
}

STDAPI
DllRegisterServer(void)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    PWSTR rgpszAlgIDs[] = { NCRYPT_KEY_STORAGE_ALGORITHM };
    CRYPT_INTERFACE_REG Interface1 = {
        NCRYPT_KEY_STORAGE_INTERFACE,
        CRYPT_LOCAL,
        sizeof(rgpszAlgIDs) / sizeof(rgpszAlgIDs[1]),
        rgpszAlgIDs };
    PCRYPT_INTERFACE_REG rgpInterfaces[1] = { &Interface1 };
    CRYPT_IMAGE_REG UM = {
        L"jwscloudksp.dll",
        sizeof(rgpInterfaces) / sizeof(rgpInterfaces[1]),
        rgpInterfaces };
    CRYPT_PROVIDER_REG Provider = {
        0,
        NULL,
        &UM,
        NULL };

    CHECK_STATUS(BCryptRegisterProvider(
        SN_KSP_PROVIDER_NAME,
        CRYPT_OVERWRITE,
        &Provider));

    CHECK_STATUS(BCryptAddContextFunctionProvider(
        CRYPT_LOCAL,
        0,
        NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM,
        SN_KSP_PROVIDER_NAME,
        CRYPT_PRIORITY_BOTTOM));

Cleanup:
    LOG_CALL(DllRegisterServer, status);
    return status;
}

STDAPI
DllUnregisterServer(void)
{
    SECURITY_STATUS status = ERROR_SUCCESS;

    status = BCryptUnregisterProvider(SN_KSP_PROVIDER_NAME);

    LOG_CALL(DllUnregisterServer, status);
    return status;
}

//
// The static cipher function table for this provider
// 
NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_KspFunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    KspOpenStorageProvider,
    KspOpenKey,
    KspCreatePersistedKey,
    KspGetProviderProperty,
    KspGetKeyProperty,
    KspSetProviderProperty,
    KspSetKeyProperty,
    KspFinalizeKey,
    KspDeleteKey,
    KspFreeProvider,
    KspFreeKey,
    KspFreeBuffer,
    KspEncrypt,
    KspDecrypt,
    KspIsAlgSupported,
    KspEnumAlgorithms,
    KspEnumKeys,
    KspImportKey,
    KspExportKey,
    KspSignHash,
    KspVerifySignature,
    KspPromptUser,
    KspNotifyChangeKey,
    KspSecretAgreement,
    KspDeriveKey,
    KspFreeSecret
};

//
// Initialize the caller's storage function table for this provider
// 

NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR  pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD    dwFlags)
{
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
    *ppFunctionTable = &g_KspFunctionTable;
    return STATUS_SUCCESS;
}
