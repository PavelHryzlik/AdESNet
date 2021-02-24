namespace AdESNet.Common
{
    // General 

    public enum Level
    {
        CMS = 0,
        XMLDSIG = 0,
        B = 1,
        T = 2,
        C = 3,
        X = 4,
        XL = 5,
        A = 6
    }

	public enum HashAlgorithm
	{
		SHA256 = 0,
		SHA384 = 1,
		SHA512 = 2
	}

	public enum TsaAuthentication
    {
        None = 0,
        JmenoHeslo = 1,
        Certifikat = 2
    }

	public enum PackagingType
	{
		Enveloped = 0,
		Enveloping = 1,
		Detached = 2
	}

    public class CertificateIdentifier 
	{	
		public byte[] CertificateHash { get; set; }
		// TODO StoreName, StoreLocation
	}

	public class AdESAttributes 
	{	
		public Level Level { get; set; }
		public HashAlgorithm HashAlgorithm { get; set; }
	}

	public class SignerAttributes 
	{	
		public string AuthorName { get; set; }
		public string Location { get; set; }
		public string Reason { get; set; }
		public string Contact { get; set; }
	}

	public class TsaProfil 
	{	
		public string TimestampServer { get; set; }
		public TsaAuthentication Authentication { get; set; }
		public string UserName { get; set; }
		public string Password { get; set; }
		public CertificateIdentifier Certificate { get; set; }
	}

	public class SignatureContext 
	{	
		public CertificateIdentifier SigningCertificate { get; set; }
		public AdESAttributes AdESAttributes { get; set; }
		public SignerAttributes SignerAttributes { get; set; }
		public TsaProfil TsaProfil { get; set; }
	}

	// PAdES

	public class PAdESSpecificAttributes
	{
		public string T { get; set; }
		public int Leftp { get; set; }
		public int Topp { get; set; }
		public int Wip { get; set; }
		public int Botp { get; set; }
	}

	public class PAdESSignatureContext 
	{	
		public CertificateIdentifier SigningCertificate { get; set; }
		public AdESAttributes AdESAttributes { get; set; }
		public SignerAttributes SignerAttributes { get; set; }
		public TsaProfil TsaProfil { get; set; }
		public PAdESSpecificAttributes PAdESSpecificAttributes { get; set; }
	}

	// XAdES
	
	public class XAdESSpecificAttributes
	{
		public PackagingType Packaging { get; set; }
	}

	public class XAdESSignatureContext 
	{	
		public CertificateIdentifier SigningCertificate { get; set; }
		public AdESAttributes AdESAttributes { get; set; }
		public SignerAttributes SignerAttributes { get; set; }
		public TsaProfil TsaProfil { get; set; }
		public XAdESSpecificAttributes XAdESSpecificAttributes { get; set; }
	}

	// Result

	public class AdESResult 
	{	
		public int Status { get; set; }
		public string Error { get; set; }
		public byte[] signedData { get; set; }
	}
}
