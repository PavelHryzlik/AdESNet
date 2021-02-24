using System;
using System.IO;
using AdESNet.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AdESNet.NetFrameworkTest
{
    [TestClass]
    public class AdESProcessorTest
    {
        private string inputCMSFile;
        private string outputCMSFile;

        private string inputPDFFile;
        private string outputPDFFile;

        private string inputXMLFile;
        private string outputXMLFile;

        private AdESProcessor adESProcessor;

        [TestInitialize]
        public void TestInitialize()
        {
            string dir = Path.GetDirectoryName(
                System.Reflection.Assembly.GetExecutingAssembly().Location);

            inputCMSFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello.txt");
            outputCMSFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.p7m");

            inputPDFFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello.pdf");
            outputPDFFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.pdf");

            inputXMLFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello.xml");
            outputXMLFile = Path.Combine(dir, "..", "..", "..", "..", @"test\AdESNet.TestData\hello_signed.xml");

            adESProcessor = new AdESProcessor();
        }

        byte[] GetCertHash(string sha1Hex)
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

        [TestMethod]
        public void CAdESSignTest()
        {
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
            var cadesResult = adESProcessor.CAdESSign(cmdDataToSign, cadesSignatureContext);

            // Save signed data to file
            File.WriteAllBytes(outputCMSFile, cadesResult.signedData);
        }

        [TestMethod]
        public void PAdESSignTest()
        {
            byte[] certHas = GetCertHash("3bd3f17836bd00f8a756e6c53fca48539da2f042");

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

            try
            {
                // PAdES sign
                var padesResult = adESProcessor.PAdESSign(pdfDataToSign, padesSignatureContext);

                // Save signed data to file
                File.WriteAllBytes(outputPDFFile, padesResult.signedData);
            }
            catch (Exception e)
            {
                throw;
            }
        }

        [TestMethod]
        public void XAdESSignTest()
        {
            byte[] certHas = GetCertHash("3bd3f17836bd00f8a756e6c53fca48539da2f042");

            // XAdES //////////////////

            // Get data to sign from file
            var xdfDataToSign = File.ReadAllBytes(inputXMLFile);

            // PAdES configuration
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
            var xadesResult = adESProcessor.XAdESSign(xdfDataToSign, xadesSignatureContext);

            // Save signed data to file
            File.WriteAllBytes(outputXMLFile, xadesResult.signedData);
        }
    }
}
