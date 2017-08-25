//////////////////////////////////////////////////////////////////////////
//
// CreateCertificate (client or server)
//
// based on a sample found at:
// http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
// Create a self-signed certificate and store it in the machine personal store
// 
#include "stdafx.h"
#include "Logging.h"
#include "CreateCertificate.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static bool
TesCryptKeyContainter(WCHAR* p_keyContainerName,DWORD p_keyFlags)
{
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY  hKey       = NULL;
  bool       result     = false;

	try
	{
		// Acquire key container
		DebugMsg(("CryptAcquireContext of existing key container... "));
		if (!CryptAcquireContextW(&hCryptProv, p_keyContainerName, nullptr, PROV_RSA_FULL, p_keyFlags))
		{
			int err = GetLastError();
      if(err == NTE_BAD_KEYSET)
      {
        LogError("**** CryptAcquireContext failed with 'bad keyset'");
      }
      else
      {
        LogError("**** Error 0x%x returned by CryptAcquireContext",err);
      }
			// Try to create a new key container
			DebugMsg(("CryptAcquireContext create new container... "));
			if (!CryptAcquireContextW(&hCryptProv, p_keyContainerName, nullptr, PROV_RSA_FULL, p_keyFlags | CRYPT_NEWKEYSET))
			{
				err = GetLastError();
        if(err == NTE_EXISTS)
        {
          LogError("**** CryptAcquireContext failed with 'already exists', are you running as administrator");
        }
        else
        {
          LogError("**** Error 0x%x returned by CryptAcquireContext",err);
        }
				// Error
				LogError("Error 0x%x", GetLastError());
        throw err;
			}
			else
			{
				DebugMsg("Success - new container created");
			}
		}
		else
		{
			DebugMsg("Success - container found");
		}


		// Generate new key pair
    // Use RSA2048BIT_KEY without any extra flags
		DebugMsg(("CryptGenKey... "));
		if (!CryptGenKey(hCryptProv, AT_SIGNATURE, 0x08000000 /*RSA2048BIT_KEY*/, &hKey))
		{
			// Error
			LogError("Error testing crypt container: 0x%x", GetLastError());
		}
		else
		{
			DebugMsg("Success testing crypt container");
      result = true;
		}
	}
  catch (...) 
  {
    LogError("Cannot acquire crypt key container");
  }

	// Clean up  

	if (hKey)
	{
		DebugMsg("CryptDestroyKey... ");
		CryptDestroyKey(hKey);
	}
	if (hCryptProv)
	{
		DebugMsg("CryptReleaseContext... ");
		CryptReleaseContext(hCryptProv, 0);
	}
  return result;
}

// Create a certificate, returning the certificate context

PCCERT_CONTEXT 
CreateCertificate(bool   p_machineCert
                 ,LPCSTR p_subject
                 ,LPCSTR p_friendlyName
                 ,LPCSTR p_description)
{
	WCHAR*     keyContainerName = L"SSLTestKeyContainer";
  DWORD      keyFlags = p_machineCert ? CRYPT_MACHINE_KEYSET : 0;

  // Test if we can create a crypt key container
  // No point in continuing if this does not succeed
  if(!TesCryptKeyContainter(keyContainerName,keyFlags))
  {
    return nullptr;
  }

	// CREATE SELF-SIGNED CERTIFICATE AND ADD IT TO PERSONAL STORE IN MACHINE PROFILE

	PCCERT_CONTEXT certContext = nullptr;
	BYTE*          pbEncoded   = nullptr;
	HCERTSTORE     hStore      = nullptr;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;

	try
	{
		// Encode certificate Subject
    CString X500(L"CN=");
    if(p_subject)
    {
      X500 += p_subject;
    }
    else
    {
      X500 += "localuser";
    }

    DWORD cbEncoded = 0;
		// Find out how many bytes are needed to encode the certificate
		DebugMsg(("CertStrToName... "));
		if (!CertStrToName(X509_ASN_ENCODING, X500, CERT_X500_NAME_STR, nullptr, pbEncoded, &cbEncoded, nullptr))
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success");
		}
		// Allocate the required space
		DebugMsg(("malloc... "));
		if (!(pbEncoded = (BYTE *)malloc(cbEncoded)))
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success");
		}
		// Encode the certificate
		DebugMsg(("CertStrToName... "));
		if (!CertStrToName(X509_ASN_ENCODING, X500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success");
		}

		// Prepare certificate Subject for self-signed certificate
		CERT_NAME_BLOB SubjectIssuerBlob;
		memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
		SubjectIssuerBlob.cbData = cbEncoded;
		SubjectIssuerBlob.pbData = pbEncoded;

		// Prepare key provider structure for certificate
		CRYPT_KEY_PROV_INFO KeyProvInfo;
		memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
		KeyProvInfo.pwszContainerName = keyContainerName; // The key we made earlier
		KeyProvInfo.pwszProvName = nullptr;
		KeyProvInfo.dwProvType   = PROV_RSA_FULL;
		KeyProvInfo.dwFlags      = keyFlags;
		KeyProvInfo.cProvParam   = 0;
		KeyProvInfo.rgProvParam  = nullptr;
		KeyProvInfo.dwKeySpec    = AT_SIGNATURE;

		// Prepare algorithm structure for certificate
		CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
		memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
		SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

		// Prepare Expiration date for certificate
		SYSTEMTIME EndTime;
		GetSystemTime(&EndTime);
		EndTime.wYear += 5;

		// Create certificate
		DebugMsg(("CertCreateSelfSignCertificate... "));
		certContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, nullptr, &EndTime, nullptr);
		if (!certContext)
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success");
		}

    // Specify the allowed usage of the certificate (client or server authentication)
		DebugMsg(("CertAddEnhancedKeyUsageIdentifier"));
    LPCSTR szOID = p_machineCert ? szOID_PKIX_KP_SERVER_AUTH : szOID_PKIX_KP_CLIENT_AUTH;
    if(CertAddEnhancedKeyUsageIdentifier(certContext, szOID))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}

    // Common variable used in several calls below
    CRYPT_DATA_BLOB cdblob;

    // Give the certificate a friendly name
    if(p_friendlyName)
    {
      cdblob.pbData = (BYTE*)p_friendlyName;
    }
    else
    {
      cdblob.pbData = (BYTE*)L"SSLStream";
    }
    cdblob.cbData = (DWORD) (wcslen((LPWSTR) cdblob.pbData) + 1) * sizeof(WCHAR);
		DebugMsg(("CertSetCertificateContextProperty CERT_FRIENDLY_NAME_PROP_ID"));
    if(CertSetCertificateContextProperty(certContext, CERT_FRIENDLY_NAME_PROP_ID, 0, &cdblob))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}

    // Give the certificate a description
    if(p_description)
    {
      cdblob.pbData = (BYTE*)p_description;
    }
    else if(p_machineCert)
    {
      cdblob.pbData = (BYTE*)L"SSLStream Server Test";
    }
    else
    {
      cdblob.pbData = (BYTE*)L"SSLStream Client Test";
    }
    cdblob.cbData = (DWORD)(wcslen((LPWSTR) cdblob.pbData) + 1) * sizeof(WCHAR);
		DebugMsg(("CertSetCertificateContextProperty CERT_DESCRIPTION_PROP_ID"));
    if (CertSetCertificateContextProperty(certContext, CERT_DESCRIPTION_PROP_ID, 0, &cdblob))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}

		// Open Personal cert store in machine or user profile
		DebugMsg(("Trying CertOpenStore to open root store... "));
		hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM
                          ,0
                          ,0
                          ,p_machineCert ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER
                          ,L"My");
		if (!hStore)
		{
			// Error
			int err = GetLastError();
      if(err == ERROR_ACCESS_DENIED)
      {
        LogError("**** CertOpenStore failed with 'access denied'. Are  you running as administrator?");
      }
      else
      {
        LogError("**** Error 0x%x returned by CertOpenStore",err);
      }
			return nullptr;
		}
		else
		{
			DebugMsg("Success opening certificate store");
		}

		// Add the cert to the store
		DebugMsg(("CertAddCertificateContextToStore... "));
		if (!CertAddCertificateContextToStore(hStore, certContext, CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success");
		}

		// Just for testing, verify that we can access cert's private key
		DWORD dwKeySpec;
		DebugMsg(("CryptAcquireCertificatePrivateKey... "));
		if (!CryptAcquireCertificatePrivateKey(certContext, 0, nullptr, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
		{
			// Error
			LogError("Error 0x%x", GetLastError());
			return nullptr;
		}
		else
		{
			DebugMsg("Success, private key acquired");
		}
	}
  catch (...)
  {
  }

  // Clean up

	if (pbEncoded != nullptr) 
  {
		DebugMsg(("free... "));
		free(pbEncoded);
		DebugMsg("Success");
	}

	if (hCryptProvOrNCryptKey)
	{
		DebugMsg("CryptReleaseContext... ");
		CryptReleaseContext(hCryptProvOrNCryptKey, 0);
		DebugMsg("Success");
	}

	if (hStore)
	{
		DebugMsg("CertCloseStore... ");
		CertCloseStore(hStore, 0);
		DebugMsg("Success");
	}
	return certContext;
}
