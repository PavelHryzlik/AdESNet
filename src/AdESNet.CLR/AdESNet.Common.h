#pragma once

using namespace System;

namespace AdESNetCLR 
{
	// General 

	public enum class Level
    {
        CMS = 0,
        XMLDSIG = 0,
        B = 1,
        T = 2,
        C = 3,
        X = 4,
        XL = 5,
        A = 6
    };

	public enum class HashAlgorithm
	{
		SHA256 = 0,
		SHA384 = 1,
		SHA512 = 2
	};

	public enum class TsaAuthentication
    {
        None = 0,
        JmenoHeslo = 1,
        Certifikat = 2
    };

	public enum class PackagingType
	{
		Enveloped = 0,
		Enveloping = 1,
		Detached = 2
	};

	public ref struct CertificateIdentifier 
	{	
		array<Byte>^ CertificateHash;
		// TODO StoreName, StoreLocation
	};

	public ref struct AdESAttributes 
	{	
		Level Level;
		HashAlgorithm HashAlgorithm;
	};

	public ref struct SignerAttributes 
	{	
		String^ AuthorName;
		String^ Location;
		String^ Reason;
		String^ Contact;
	};

	public ref struct TsaProfil 
	{	
		String^ TimestampServer;
		TsaAuthentication Authentication;
		String^ UserName;
		String^ Password;
		CertificateIdentifier Certificate;
	};

	public ref struct SignatureContext 
	{	
		CertificateIdentifier^ SigningCertificate;
		AdESAttributes^ AdESAttributes;
		SignerAttributes^ SignerAttributes;
		TsaProfil^ TsaProfil;
	};

	// PAdES

	public ref struct PAdESSpecificAttributes
	{
		String^ T;
		int Leftp = 1;
		int Topp = 1;
		int Wip = 50;
		int Botp = 5;
	};

	public ref struct PAdESSignatureContext 
	{	
		CertificateIdentifier^ SigningCertificate;
		AdESAttributes^ AdESAttributes;
		SignerAttributes^ SignerAttributes;
		TsaProfil^ TsaProfil;
		PAdESSpecificAttributes^ PAdESSpecificAttributes;
	};

	// XAdES
	
	public ref struct XAdESSpecificAttributes
	{
		PackagingType Packaging;
	};

	public ref struct XAdESSignatureContext 
	{	
		CertificateIdentifier^ SigningCertificate;
		AdESAttributes^ AdESAttributes;
		SignerAttributes^ SignerAttributes;
		TsaProfil^ TsaProfil;
		XAdESSpecificAttributes^ XAdESSpecificAttributes;
	};

	// Result

	public ref struct AdESResult 
	{	
		int Status;
		String^ Error;
		array<Byte>^ signedData;
	};
}
