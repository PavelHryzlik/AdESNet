#include "pch.h"

#include <exception>
#include "AdESNet.CLR.h"

namespace AdESNetCLR
{
	std::vector<PCCRL_CONTEXT> GetCRLs(PCCERT_CONTEXT p)
	{
		std::vector<PCCRL_CONTEXT> d;
		if (!p)
			return d;

		auto hStore = CertOpenSystemStore(
			0,
			L"CA");
		PCCRL_CONTEXT crl = 0;
		for (;;)
			{
			crl = CertEnumCRLsInStore(hStore, crl);
			if (!crl)
				break;

			d.push_back(CertDuplicateCRLContext(crl));
			}
			CertCloseStore(hStore, 0);
		return d;
	}

	std::vector<PCCERT_CONTEXT> GetChain(PCCERT_CONTEXT cert)
	{
		std::vector<PCCERT_CONTEXT> d;
		if (!cert)
			return d;

		PCCERT_CHAIN_CONTEXT CC = 0;
		CERT_CHAIN_PARA CCP = { 0 };
		CCP.cbSize = sizeof(CCP);
		CCP.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
		CERT_ENHKEY_USAGE        EnhkeyUsage = { 0 };
		CCP.RequestedUsage.Usage = EnhkeyUsage;
		CertGetCertificateChain(0, cert, 0, 0, &CCP, 0, 0, &CC);
		if (CC)
		{
			for (DWORD i = 0; i < CC->cChain; i++)
			{
				PCERT_SIMPLE_CHAIN ccc = CC->rgpChain[i];
				for (DWORD ii = 0; ii < ccc->cElement; ii++)
				{
					PCERT_CHAIN_ELEMENT el = ccc->rgpElement[ii];
					// Dup check
					bool D = false;
					for (auto& ec : d)
					{
						if (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ec->pCertInfo, el->pCertContext->pCertInfo))
						{
							D = true;
						}
						if (CertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ec->pCertInfo, cert->pCertInfo))
						{
							D = true;
						}
					}
					if (!D)
						d.push_back(el->pCertContext);
				}
			}
		}
		return d;
	}

	std::vector<AdES::CERT>* GetCert(array<Byte>^ certificateHash)
	{
		// Find signing certificate
		auto hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		0,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"My");

		array<Byte>^ certHash = certificateHash;

		pin_ptr<System::Byte> pCertificateThumbprint = &certHash[0];
		CRYPT_HASH_BLOB blob;
		blob.cbData = certHash->Length;
		blob.pbData = static_cast<BYTE *>(pCertificateThumbprint);

		PCCERT_CONTEXT cert = CertFindCertificateInStore(
		hSystemStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_FIND_SHA1_HASH,
		&blob,
		NULL);

		// Create cert
		auto certs = new std::vector<AdES::CERT>();
		AdES::CERT ce;
		ce.cert.cert = cert;
		ce.cert.Crls = GetCRLs(ce.cert.cert);

		// Also the chain
		auto ch = GetChain(cert);
		for (auto& c : ch)
		{
			AdES::CERTANDCRL ce2;
			ce2.cert = c;
			ce2.Crls = GetCRLs(ce2.cert);
			ce.More.push_back(ce2);
		}
		certs->push_back(ce);

		if(cert)
			CertFreeCertificateContext(cert);
		if(hSystemStore)
			CertCloseStore(hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);

		return certs;
	}

	AdESResult^ AdESWrapper::CAdESSign(
		array<Byte>^ dataToSign, 
		SignatureContext^ signatureContext)
	{
		if (signatureContext == nullptr ||
			signatureContext->SigningCertificate == nullptr ||
			signatureContext->AdESAttributes == nullptr)
		{
			throw gcnew System::Exception(gcnew System::String("Argument exception: Mandatory data missing"));
		}

		// Level
		AdES::LEVEL nativeLevel = static_cast<AdES::LEVEL>(signatureContext->AdESAttributes->Level);

		// Data to Sign
		pin_ptr<System::Byte> pDataToSign = &dataToSign[0];
		unsigned char* pbyDataToSign = pDataToSign;
		char* pchDataToSign = reinterpret_cast<char*>(pbyDataToSign);

		// Get cert
		std::vector<AdES::CERT>* cert = GetCert(signatureContext->SigningCertificate->CertificateHash);

		// Params
		auto params = new AdES::SIGNPARAMETERS();
		params->Attached = AdES::ATTACHTYPE::ATTACHED;
		params->Policy = "1.3.6.1.5.5.7.48.1";
		params->commitmentTypeOid = "1.2.840.113549.1.9.16.6.1";
		params->Debug = IsDebug;
		params->PAdES = false;
		switch (signatureContext->AdESAttributes->HashAlgorithm)
		{
		case AdESNetCLR::HashAlgorithm::SHA256:
			params->HashAlgorithm = { szOID_NIST_sha256 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA384:
			params->HashAlgorithm = { szOID_NIST_sha384 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA512:
			params->HashAlgorithm = { szOID_NIST_sha512 };
			break;
		}	

		if (signatureContext->TsaProfil &&
			signatureContext->TsaProfil->TimestampServer)
		{
			String^ timestampServer = signatureContext->TsaProfil->TimestampServer;
			params->TSServer = msclr::interop::marshal_as<std::wstring>(timestampServer);
		}

		// Sig
		auto sig = new std::vector<char>();

		// PAdES sign
		HRESULT res = m_AdES->Sign(nativeLevel, pchDataToSign, strlen(pchDataToSign), *cert, *params, *sig);		

		auto signedData = gcnew array<Byte>(sig->size()); 
		// convert any native pointer to IntPtr by doing C-Style cast
		pin_ptr<byte> byteArrayStart = &signedData[0];
		memcpy(byteArrayStart, sig->data(), sig->size());

		AdESResult^ result = gcnew AdESResult();
		result->Status = res;
		result->Error = "";
		result->signedData = signedData;
		
		return result;
	}

	AdESResult^ AdESWrapper::PAdESSign(
		array<Byte>^ dataToSign, 
		PAdESSignatureContext^ signatureContext)
	{
		if (signatureContext == nullptr ||
			signatureContext->SigningCertificate == nullptr ||
			signatureContext->AdESAttributes == nullptr)
		{
			throw gcnew System::Exception(gcnew System::String("Argument exception: Mandatory data missing"));
		}

		// Level
		AdES::LEVEL nativeLevel = static_cast<AdES::LEVEL>(signatureContext->AdESAttributes->Level);

		// Data to Sign
		pin_ptr<System::Byte> pDataToSign = &dataToSign[0];
		unsigned char* pbyDataToSign = pDataToSign;
		char* pchDataToSign = reinterpret_cast<char*>(pbyDataToSign);
		
		/*std::vector<char> data;
		int tam = strlen(pchDataToSign);
		data.resize(tam);
		pin_ptr<char> pinned = &pchDataToSign[0];
		std::memcpy(data.data(), pinned, tam);*/

		// Get cert
		std::vector<AdES::CERT>* cert = GetCert(signatureContext->SigningCertificate->CertificateHash);

		// Params
		auto params = new AdES::SIGNPARAMETERS();
		params->Attached = AdES::ATTACHTYPE::DETACHED;
		params->Policy = "1.3.6.1.5.5.7.48.1";
		params->commitmentTypeOid = "1.2.840.113549.1.9.16.6.1";

		if (signatureContext->SignerAttributes)
		{
			if (signatureContext->SignerAttributes->AuthorName)
			{
				String^ authorName = signatureContext->SignerAttributes->AuthorName;
				params->pdfparams.Name = msclr::interop::marshal_as<std::string>(authorName);
			}
			if (signatureContext->SignerAttributes->Location)
			{
				String^ location = signatureContext->SignerAttributes->Location;
				params->pdfparams.Location = msclr::interop::marshal_as<std::string>(location);
			}
			if (signatureContext->SignerAttributes->Reason)
			{
				String^ reason = signatureContext->SignerAttributes->Reason;
				params->pdfparams.Reason = msclr::interop::marshal_as<std::string>(reason);
			}
			if (signatureContext->SignerAttributes->Contact)
			{
				String^ contact = signatureContext->SignerAttributes->Contact;
				params->pdfparams.Contact = msclr::interop::marshal_as<std::string>(contact);
			}
		}
		params->Debug = IsDebug;
		params->PAdES = true;
		switch (signatureContext->AdESAttributes->HashAlgorithm)
		{
		case AdESNetCLR::HashAlgorithm::SHA256:
			params->HashAlgorithm = { szOID_NIST_sha256 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA384:
			params->HashAlgorithm = { szOID_NIST_sha384 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA512:
			params->HashAlgorithm = { szOID_NIST_sha512 };
			break;
		}	

		if (signatureContext->TsaProfil &&
			signatureContext->TsaProfil->TimestampServer)
		{
			String^ timestampServer = signatureContext->TsaProfil->TimestampServer;
			params->TSServer = msclr::interop::marshal_as<std::wstring>(timestampServer);
		}

		// Sig
		auto sig = new std::vector<char>();

		// PAdES sign
		HRESULTERROR res = m_AdES->PDFSign(nativeLevel, pchDataToSign, strlen(pchDataToSign), *cert, *params, *sig);		

		auto signedData = gcnew array<Byte>(sig->size()); 
		// convert any native pointer to IntPtr by doing C-Style cast
		pin_ptr<byte> byteArrayStart = &signedData[0];
		memcpy(byteArrayStart, sig->data(), sig->size());

		AdESResult^ result = gcnew AdESResult();
		result->Status = res.hr;
		result->Error = msclr::interop::marshal_as<String^>(res.err);
		result->signedData = signedData;

		return result;
	}

	AdESResult^ AdESWrapper::XAdESSign(
		array<Byte>^ dataToSign, 
		XAdESSignatureContext^ signatureContext)
	{
		if (signatureContext == nullptr ||
			signatureContext->SigningCertificate == nullptr ||
			signatureContext->AdESAttributes == nullptr ||
			signatureContext->XAdESSpecificAttributes == nullptr)
		{
			throw gcnew System::Exception(gcnew System::String("Argument exception: Mandatory data missing"));
		}

		// Level
		AdES::LEVEL nativeLevel = static_cast<AdES::LEVEL>(signatureContext->AdESAttributes->Level);

		// Data to Sign
		pin_ptr<System::Byte> pDataToSign = &dataToSign[0];
		unsigned char* pbyDataToSign = pDataToSign;
		char* pchDataToSign = reinterpret_cast<char*>(pbyDataToSign);

		// Get cert
		std::vector<AdES::CERT>* cert = GetCert(signatureContext->SigningCertificate->CertificateHash);

		// Params
		auto params = new AdES::SIGNPARAMETERS();
		switch (signatureContext->XAdESSpecificAttributes->Packaging)
		{
		case AdESNetCLR::PackagingType::Enveloping:
			params->Attached = AdES::ATTACHTYPE::ENVELOPING;
			break;
		case AdESNetCLR::PackagingType::Enveloped:
			params->Attached = AdES::ATTACHTYPE::ENVELOPED;
			break;
		case AdESNetCLR::PackagingType::Detached:
			params->Attached = AdES::ATTACHTYPE::DETACHED;
			break;
		default:
			params->Attached = AdES::ATTACHTYPE::ENVELOPED;
			break;
		}
		params->Policy = "1.3.6.1.5.5.7.48.1";
		params->commitmentTypeOid = "1.2.840.113549.1.9.16.6.1";
		params->Debug = IsDebug;
		params->PAdES = false;
		switch (signatureContext->AdESAttributes->HashAlgorithm)
		{
		case AdESNetCLR::HashAlgorithm::SHA256:
			params->HashAlgorithm = { szOID_NIST_sha256 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA384:
			params->HashAlgorithm = { szOID_NIST_sha384 };
			break;
		case AdESNetCLR::HashAlgorithm::SHA512:
			params->HashAlgorithm = { szOID_NIST_sha512 };
			break;
		}	

		if (signatureContext->TsaProfil &&
			signatureContext->TsaProfil->TimestampServer)
		{
			String^ timestampServer = signatureContext->TsaProfil->TimestampServer;
			params->TSServer = msclr::interop::marshal_as<std::wstring>(timestampServer);
		}

		// Sig
		auto sig = new std::vector<char>();

		// TODO
		AdES::FILEREF a1(pchDataToSign, 0, "blahblah1");
		std::vector<AdES::FILEREF> ax = { a1 };

		// PAdES sign
		HRESULT res = m_AdES->XMLSign(nativeLevel, ax, *cert, *params, *sig);		

		auto signedData = gcnew array<Byte>(sig->size()); 
		// convert any native pointer to IntPtr by doing C-Style cast
		pin_ptr<byte> byteArrayStart = &signedData[0];
		memcpy(byteArrayStart, sig->data(), sig->size());

		AdESResult^ result = gcnew AdESResult();
		result->Status = res;
		result->Error = "";
		result->signedData = signedData;
		
		return result;
	}
}



