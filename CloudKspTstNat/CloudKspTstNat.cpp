/* Copyright (C) 2016 JW Secure, Inc. - All Rights Reserved
*  You may use, distribute and modify this code under the terms of the GPLv3
*  license: https://www.gnu.org/licenses/gpl-3.0-standalone.html.
*  This program comes with ABSOLUTELY NO WARRANTY.
*/

#include "stdafx.h"

#define wszVERB_CREATE                                  L"CREATE"
#define wszVERB_USE                                     L"USE"
#define wszVERB_DELETE                                  L"DELETE"
#define SN_KSP_PROVIDER_NAME					        L"JW Secure Cloud Key Storage Provider"

//
// Flow macros
//

static
void
WINAPI
_OutputDbgStr(
    __in  LPSTR szFile,
    __in  DWORD dwLine,
    __in  LPSTR szMsg,
    __in  DWORD dwStatus)
{
    CHAR rgsz[256];
    LPSTR szTag = "INFO";

    if (0 != dwStatus)
        szTag = "ERROR";

    StringCbPrintfA(
        rgsz,
        sizeof(rgsz),
        "%s: %s - 0x%x, file %s, line %d\n",
        szTag,
        szMsg,
        dwStatus,
        szFile,
        dwLine);
    printf(rgsz);
}

#define CHECK_COM(_X) {												\
    if (FAILED(hr = _X)) {											\
        _OutputDbgStr(__FILE__, __LINE__, #_X, (DWORD) hr);			\
        _com_issue_error(hr);										\
    }                                                               \
}

#define CHECK_BOOL(_X) {											\
    if (FALSE == _X) {												\
		hr = (HRESULT) GetLastError();								\
        _OutputDbgStr(__FILE__, __LINE__, #_X, (DWORD) hr);			\
        _com_issue_error(hr);                                       \
    }                                                               \
}

#define CHECK_PTR(_X) {												\
    if (NULL == (_X)) {												\
		hr = (HRESULT) GetLastError();								\
        _OutputDbgStr(__FILE__, __LINE__, #_X, (DWORD) hr);			\
		_com_issue_error(hr);                                       \
    }                                                               \
}

#define CHECK_ALLOC(_X) {                                           \
    if (NULL == (_X)) {                                             \
		hr = E_OUTOFMEMORY;											\
		_com_issue_error(hr);										\
    }                                                               \
}

//
// Heap Helpers
//

static void* _Alloc(size_t size)
{
    return CoTaskMemAlloc(size);
}

static void _Free(void* pv)
{
    CoTaskMemFree(pv);
}

void Usage()
{
    printf("Usage: CloudKspTstNat.exe [ [ C | PCP | SC ] [ CREATE | USE | DELETE ] ] | [ INVALIDATE ]\n");
    printf("\n C  : Cloud\n");
    printf(" PCP : Platform Crypto Provider\n");
    printf(" SC  : Smart Card\n");
}

//
// Write hex bytes to console output
//
#define CROW                                                16
static void PrintBytes(LPSTR szTitle, PBYTE pbData, DWORD cbData)
{
    DWORD iByte = 0, iRowItem = 0;
    CHAR rgbRow[100];

    StringCbPrintfA(
        rgbRow, sizeof(rgbRow), "\n%s -- %d bytes\n", szTitle, cbData);
    printf(rgbRow);

    while (iByte < cbData)
    {
        for (iRowItem = 0;
            iRowItem < CROW && iByte < cbData;
            iRowItem++, iByte++)
            StringCbPrintfA(
                rgbRow + (iRowItem * 3),
                sizeof(rgbRow) - (iRowItem * 3),
                "%02X ",
                pbData[iByte]);

        printf(rgbRow);
        printf("\n");
    }
}

PWSTR g_wszTestKeyName = L"CloudKspTstKey";

HRESULT
DeleteKeyTest(LPWSTR wszProviderName)
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hTpmKey = NULL;

    try
    {
        //
        // Open the KSP
        //
        CHECK_COM(NCryptOpenStorageProvider(
            &hProv,
            wszProviderName,
            0));

        CHECK_COM(NCryptDeleteKey(hTpmKey, 0));
        hTpmKey = NULL;

        NCryptFreeObject(hProv);
    }
    catch (_com_error cErr)
    {
        hr = cErr.Error();
        printf("Failed - 0x%x\n", hr);
    }
    catch (HRESULT hrException)
    {
        hr = hrException;
        printf("Failed - 0x%x\n", hr);
    }

    if (NULL != hTpmKey)
        NCryptFreeObject(hTpmKey);

    if (NULL != hProv)
        NCryptFreeObject(hProv);

    return hr;
}

HRESULT
KeyTest(
    LPWSTR wszProviderName,
    LPWSTR wszKeyName,
    BOOL fMachineKey,
    BOOL fUseExisting,
    BOOL fOneShot)
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hTpmKey = NULL;
    PBYTE pbPubKey = NULL;
    DWORD cbPubKey = 0;
    BYTE rgbPubKeyHash[32];
    DWORD cbPubKeyHash = sizeof(rgbPubKeyHash);
    BOOL fIsTrusted = FALSE;
    BCRYPT_PKCS1_PADDING_INFO PaddingInfo = { 0 };
    PBYTE pbSignature = NULL;
    DWORD cbSignature = 0;
    HKEY hReg = NULL;
    PBYTE pbEkPub = NULL;
    DWORD cbEkPub = 0;
    PBYTE pbPcr7Hash = NULL;
    DWORD cbPcr7Hash = 0;

    try
    {
        //
        // Open the KSP
        //

        CHECK_COM(NCryptOpenStorageProvider(
            &hProv,
            wszProviderName,
            0));

        if (!fUseExisting)
        {
            //
            // Create a new key
            //

            CHECK_COM(NCryptCreatePersistedKey(
                hProv,
                &hTpmKey,
                BCRYPT_RSA_ALGORITHM,
                wszKeyName,
                0,
                fMachineKey ? NCRYPT_MACHINE_KEY_FLAG : 0));

            CHECK_COM(NCryptFinalizeKey(hTpmKey, 0));
        }
        else
        {
            //
            // Open an existing key
            //

            CHECK_COM(NCryptOpenKey(
                hProv,
                &hTpmKey,
                wszKeyName,
                0,
                fMachineKey ? NCRYPT_MACHINE_KEY_FLAG : 0));
        }

        printf(
            "Opened key %S with %S\n",
            wszKeyName,
            wszProviderName);

        //
        // Export the public
        //

        CHECK_COM(NCryptExportKey(
            hTpmKey,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            NULL,
            NULL,
            0,
            &cbPubKey,
            0));

        CHECK_ALLOC(pbPubKey = (PBYTE)_Alloc(cbPubKey));

        CHECK_COM(NCryptExportKey(
            hTpmKey,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            NULL,
            pbPubKey,
            cbPubKey,
            &cbPubKey,
            0));


        //
        // Use the private key
        //

        PaddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        CHECK_COM(NCryptSignHash(
            hTpmKey,
            &PaddingInfo,
            rgbPubKeyHash,
            cbPubKeyHash,
            NULL,
            0,
            &cbSignature,
            BCRYPT_PAD_PKCS1));

        CHECK_ALLOC(pbSignature = (PBYTE)_Alloc(cbSignature));

        CHECK_COM(NCryptSignHash(
            hTpmKey,
            &PaddingInfo,
            rgbPubKeyHash,
            cbPubKeyHash,
            pbSignature,
            cbSignature,
            &cbSignature,
            BCRYPT_PAD_PKCS1));

        printf("Success");
    }
    catch (_com_error cErr)
    {
        hr = cErr.Error();
        printf("Failed - 0x%x\n", hr);
    }
    catch (HRESULT hrException)
    {
        hr = hrException;
        printf("Failed - 0x%x\n", hr);
    }

    if (NULL != hReg)
        RegCloseKey(hReg);
    if (NULL != pbSignature)
        _Free(pbSignature);
    if (NULL != pbPubKey)
        _Free(pbPubKey);
    if (NULL != hTpmKey)
        NCryptFreeObject(hTpmKey);
    if (NULL != hProv)
        NCryptFreeObject(hProv);

    return hr;
}

#define CREATE                  0x1
#define USE                     0x2
#define DELETEKEY               0x4
#define USAGE                   0x10

#define CREATE_ARG              L"CREATE"
#define USE_ARG                 L"USE"
#define DELETE_ARG              L"DELETE"
#define USERKEYNAME_ARG         L"-u"
#define MACHINEKEYNAME_ARG      L"-m"

#define PCP_ARG                 L"PCP"
#define SC_ARG                  L"SC"
#define SN_ARG                  L"C"

int _tmain(int argc, __in_ecount(argc) _TCHAR* argv[])
{
    HRESULT hr = S_OK;
    DWORD action = USAGE;
    BOOL fUseExisting = FALSE;
    LPWSTR wszProviderName = NULL;
    LPWSTR wszKeyName = g_wszTestKeyName;
    BOOL fMachineKey = FALSE;
    BOOL fOneShot = FALSE;

    CoInitialize(NULL);

    // TODO
    printf("Hit any key...\n");
    getchar();

    /* parse arguments */
    for (int i = 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], USERKEYNAME_ARG))
        {
            if (i < argc - 1)
            {
                i++;
                wszKeyName = argv[i];
            }
            else
            {
                action = USAGE;
                break;
            }
        }
        else if (!_wcsicmp(argv[i], MACHINEKEYNAME_ARG))
        {
            if (i < argc - 1)
            {
                i++;
                wszKeyName = argv[i];
                fMachineKey = TRUE;
            }
            else
            {
                action = USAGE;
                break;
            }
        }
        else if (!_wcsicmp(argv[i], CREATE_ARG))
        {
            action = CREATE;
        }
        else if (!_wcsicmp(argv[i], USE_ARG))
        {
            fUseExisting = TRUE;
            action = USE;
        }
        else if (!_wcsicmp(argv[i], DELETE_ARG))
        {
            action = DELETEKEY;
        }
        else if (!_wcsicmp(argv[i], SN_ARG))
        {
            wszProviderName = SN_KSP_PROVIDER_NAME;
        }
        else if (!_wcsicmp(argv[i], SC_ARG))
        {
            wszProviderName = MS_SMART_CARD_KEY_STORAGE_PROVIDER;
        }
        else if (!_wcsicmp(argv[i], PCP_ARG))
        {
            wszProviderName = MS_PLATFORM_CRYPTO_PROVIDER;
        }
    }

    if (NULL == wszProviderName)
    {
        action = USAGE;
    }

    switch (action)
    {
    case CREATE:
    case USE:
        hr = KeyTest(
            wszProviderName, wszKeyName, fMachineKey, fUseExisting, fOneShot);
        break;
    case DELETEKEY:
        hr = DeleteKeyTest(wszProviderName);
        break;
    default:
        hr = E_INVALIDARG;
        Usage();
    }

    return (int)hr;
}