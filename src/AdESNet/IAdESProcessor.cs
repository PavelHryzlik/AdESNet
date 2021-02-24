using System.Threading.Tasks;
using AdESNet.Common;

namespace AdESNet
{
    public interface IAdESProcessor
    {
        AdESResult CAdESSign(byte[] dataToSign, SignatureContext signatureContext);

        Task<AdESResult> CAdESSignAsync(byte[]  dataToSign, SignatureContext signatureContext);

        AdESResult PAdESSign(byte[]  dataToSign, PAdESSignatureContext signatureContext);

        Task<AdESResult> PAdESSignAsync(byte[]  dataToSign, PAdESSignatureContext signatureContext);

        AdESResult XAdESSign(byte[]  dataToSign, XAdESSignatureContext signatureContext);

        Task<AdESResult> XAdESSignAsync(byte[]  dataToSign, XAdESSignatureContext signatureContext);
    }
}
