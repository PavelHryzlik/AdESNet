using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using AdESNetCLR;

namespace AdESNet.ConsoleTest
{
    class Program
    {
        private static string inputCMSFile;
        private static string outputCMSFile;

        private static string inputPDFFile;
        private static string outputPDFFile;

        private static string inputXMLFile;
        private static string outputXMLFile;

        const string MY = "MY";
        const string OTHERS = "AddressBook";

        static X509Certificate GetCert()
        {
            IntPtr hCertCntxt = IntPtr.Zero;
            IntPtr hStore = IntPtr.Zero;

            hStore = Crypto32.CertOpenStore(Crypto32.CERT_STORE_PROV_SYSTEM,
                                            Crypto32.MY_ENCODING_TYPE,
                                            IntPtr.Zero,
                                            Crypto32.CERT_SYSTEM_STORE_CURRENT_USER,
                                            MY);

            String sha1Hex = "3bd3f17836bd00f8a756e6c53fca48539da2f042";

            // Convert to bin
            int tam = sha1Hex.Length / 2;
            byte[] sha1Bin = new byte[tam];

            int aux = 0;
            for (int i = 0; i < tam; ++i)
            {
                String str = sha1Hex.Substring(aux, 2);
                sha1Bin[i] = (byte)Convert.ToInt32(str, 16);
                aux = aux + 2;
            }

            Crypto32.CRYPTOAPI_BLOB cryptBlob;
            cryptBlob.cbData = sha1Bin.Length;
            GCHandle h1 = default(GCHandle);
            GCHandle h2 = default(GCHandle);
            try
            {
                h1 = GCHandle.Alloc(sha1Bin, GCHandleType.Pinned);
                cryptBlob.pbData = h1.AddrOfPinnedObject();
                h2 = GCHandle.Alloc(cryptBlob, GCHandleType.Pinned);
                hCertCntxt = Crypto32.CertFindCertificateInStore(
                    hStore,
                    Crypto32.MY_ENCODING_TYPE,
                    0,
                    Crypto32.CERT_FIND_SHA1_HASH,
                    h2.AddrOfPinnedObject(),
                    IntPtr.Zero);
            }
            finally
            {
                if (h1 != default(GCHandle)) h1.Free();
                if (h2 != default(GCHandle)) h2.Free();
            }

            X509Certificate cert = null; 
            if (hCertCntxt != IntPtr.Zero)
            { 
                cert = new X509Certificate(hCertCntxt);
            }

            if (hCertCntxt != IntPtr.Zero)
                Crypto32.CertFreeCertificateContext(hCertCntxt);
            if (hStore != IntPtr.Zero)
                Crypto32.CertCloseStore(hStore, 0);

            return cert;
        }

        static void TestCrypto32()
        {
            IntPtr hCertCntxt = IntPtr.Zero;
            IntPtr hStore = IntPtr.Zero;

            hStore = Crypto32.CertOpenStore(Crypto32.CERT_STORE_PROV_SYSTEM,
                                            Crypto32.MY_ENCODING_TYPE,
                                            IntPtr.Zero,
                                            Crypto32.CERT_SYSTEM_STORE_CURRENT_USER,
                                            MY);

            Console.WriteLine("Store Handle:\t0x{0:X}", hStore.ToInt64());

            String sha1Hex = "3bd3f17836bd00f8a756e6c53fca48539da2f042";

            // Convert to bin
            int tam = sha1Hex.Length / 2;
            byte[] sha1Bin = new byte[tam];

            int aux = 0;
            for (int i = 0; i < tam; ++i)
            {
                String str = sha1Hex.Substring(aux, 2);
                sha1Bin[i] = (byte)Convert.ToInt32(str, 16);
                aux = aux + 2;
            }

            Crypto32.CRYPTOAPI_BLOB cryptBlob;
            cryptBlob.cbData = sha1Bin.Length;
            GCHandle h1 = default(GCHandle);
            GCHandle h2 = default(GCHandle);
            try
            {
                h1 = GCHandle.Alloc(sha1Bin, GCHandleType.Pinned);
                cryptBlob.pbData = h1.AddrOfPinnedObject();
                h2 = GCHandle.Alloc(cryptBlob, GCHandleType.Pinned);
                hCertCntxt = Crypto32.CertFindCertificateInStore(
                    hStore,
                    Crypto32.MY_ENCODING_TYPE,
                    0,
                    Crypto32.CERT_FIND_SHA1_HASH,
                    h2.AddrOfPinnedObject(),
                    IntPtr.Zero);
            }
            finally
            {
                if (h1 != default(GCHandle)) h1.Free();
                if (h2 != default(GCHandle)) h2.Free();
            }

            if (hCertCntxt != IntPtr.Zero)
            {  //use certcontext from managed code
                Console.WriteLine("CertContext:\t0x{0:X}", hCertCntxt.ToInt64());
                X509Certificate foundcert = new X509Certificate(hCertCntxt);
                Console.WriteLine("\nFound certificate with Thumbprint \"{0}\"", sha1Hex);
                Console.WriteLine("SubjectName:\t{0}", foundcert.GetName());
                Console.WriteLine("Serial No:\t{0}", foundcert.GetSerialNumberString());
                Console.WriteLine("HashString:\t{0}", foundcert.GetCertHashString());
            }
            else
                Console.WriteLine("Could not find certificate containing Thumbprint \"{0}\"", sha1Hex);

            if (hCertCntxt != IntPtr.Zero)
                Crypto32.CertFreeCertificateContext(hCertCntxt);
            if (hStore != IntPtr.Zero)
                Crypto32.CertCloseStore(hStore, 0);

            //IntPtr hSysStore = IntPtr.Zero;
            //IntPtr hCertCntxt = IntPtr.Zero;

            //hSysStore = Crypto32.CertOpenSystemStore(IntPtr.Zero, MY);
            //Console.WriteLine("Store Handle:\t0x{0:X}", hSysStore.ToInt32());

            //if (hSysStore != IntPtr.Zero)
            //{
            //    hCertCntxt = Crypto32.CertFindCertificateInStore(
            //        hSysStore,
            //        MY_ENCODING_TYPE,
            //        0,
            //        CERT_FIND_SUBJECT_STR,
            //        lpszCertSubject,
            //        IntPtr.Zero);

            //    if (hCertCntxt != IntPtr.Zero)
            //    {  //use certcontext from managed code
            //        Console.WriteLine("CertContext:\t0x{0:X}", hCertCntxt.ToInt32());
            //        X509Certificate foundcert = new X509Certificate(hCertCntxt);
            //        Console.WriteLine("\nFound certificate with SubjectName string \"{0}\"", lpszCertSubject);
            //        Console.WriteLine("SubjectName:\t{0}", foundcert.GetName());
            //        Console.WriteLine("Serial No:\t{0}", foundcert.GetSerialNumberString());
            //        Console.WriteLine("HashString:\t{0}", foundcert.GetCertHashString());
            //    }
            //    else
            //        Console.WriteLine("Could not find SubjectName containing string \"{0}\"", lpszCertSubject);
            //}
            ////-------  Clean Up  -----------
            //if (hCertCntxt != IntPtr.Zero)
            //    Crypto32.CertFreeCertificateContext(hCertCntxt);
            //if (hSysStore != IntPtr.Zero)
            //    Crypto32.CertCloseStore(hSysStore, 0);
        }

        static byte[] GetCertHash(string sha1Hex)
        {
            // Convert to bin
            int tam = sha1Hex.Length / 2;
            byte[] sha1Bin = new byte[tam];

            int aux = 0;
            for (int i = 0; i < tam; ++i)
            {
                String str = sha1Hex.Substring(aux, 2);
                sha1Bin[i] = (byte)Convert.ToInt32(str, 16);
                aux = aux + 2;
            }

            return sha1Bin;
        }

        static void Main(string[] args)
        {
            string dir = Path.GetDirectoryName(
                System.Reflection.Assembly.GetExecutingAssembly().Location);

            inputCMSFile = Path.Combine(dir, "..", "..", "..", "..", "..", @"test\AdESNet.TestData\hello.txt");
            outputCMSFile = Path.Combine(dir, "..", "..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.p7m");

            inputPDFFile = Path.Combine(dir, "..","..", "..", "..", "..", @"test\AdESNet.TestData\hello.pdf");
            outputPDFFile = Path.Combine(dir, "..","..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.pdf");

            inputXMLFile = Path.Combine(dir, "..", "..", "..", "..", "..", @"test\AdESNet.TestData\hello.xml");
            outputXMLFile = Path.Combine(dir, "..", "..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.xml");

            //TestCrypto32();
            //var cert = GetCert();

            // Cpp object
            using var wr = new AdESWrapper {IsDebug = true};

            byte[] certHas = GetCertHash("3bd3f17836bd00f8a756e6c53fca48539da2f042");

            // CAdES //////////////////

            // Get data to sign from file
            var cmdDataToSign = File.ReadAllBytes(inputCMSFile);

            // CAdES configuration
            var cadesSignatureContext = new SignatureContext
            {
                SigningCertificate = new CertificateIdentifier
                {
                    CertificateHash = certHas
                },
                AdESAttributes = new AdESAttributes
                {
                    Level = Level.XL,
                    HashAlgorithm = HashAlgorithm.SHA256
                },
                SignerAttributes = new SignerAttributes
                {
                    AuthorName = "Pavel Hryzlík"
                }
            };

            // CAdES sign
            var cadesResult = wr.CAdESSign(cmdDataToSign, cadesSignatureContext);

            // Save signed data to file
            File.WriteAllBytes(outputCMSFile, cadesResult.signedData);

            // PAdES //////////////////

            // Get data to sign from file
            var pdfDataToSign = File.ReadAllBytes(inputPDFFile);

            // PAdES configuration
            var padesSignatureContext = new PAdESSignatureContext
            {
                SigningCertificate = new CertificateIdentifier
                {
                    CertificateHash = certHas
                },
                AdESAttributes = new AdESAttributes
                {
                    Level = Level.XL,
                    HashAlgorithm = HashAlgorithm.SHA256
                },
                SignerAttributes = new SignerAttributes
                {
                    AuthorName = "Pavel Hryzlík"
                },
                PAdESSpecificAttributes =  new PAdESSpecificAttributes { }
            };

            // PAdES sign
            var padesResult = wr.PAdESSign(pdfDataToSign, padesSignatureContext);

            // Save signed data to file
            File.WriteAllBytes(outputPDFFile, padesResult.signedData);

            // XAdES //////////////////

            // Get data to sign from file
            var xdfDataToSign = File.ReadAllBytes(inputXMLFile);

            // XAdES configuration
            var xadesSignatureContext = new XAdESSignatureContext
            {
                SigningCertificate = new CertificateIdentifier
                {
                    CertificateHash = certHas
                },
                AdESAttributes = new AdESAttributes
                {
                    Level = Level.XL,
                    HashAlgorithm = HashAlgorithm.SHA256
                },
                SignerAttributes = new SignerAttributes
                {
                    AuthorName = "Pavel Hryzlík"
                },
                XAdESSpecificAttributes =  new XAdESSpecificAttributes
                {
                    Packaging = PackagingType.Enveloped
                }
            };

            // XAdES sign
            var xadesResult = wr.XAdESSign(xdfDataToSign, xadesSignatureContext);

            // Save signed data to file
            File.WriteAllBytes(outputXMLFile, xadesResult.signedData);
        }
    }
}
