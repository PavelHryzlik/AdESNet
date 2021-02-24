using System.Threading.Tasks;
using AdESNet.Common;

namespace AdESNet
{
    public class AdESProcessor : IAdESProcessor
    {
        public AdESResult CAdESSign(byte[] dataToSign, SignatureContext signatureContext)
        {
            AdESResult result;
#if NET5_0
            using (dynamic wr = CLRLoader.CLRLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRWrapperClassName))
#else
            using (dynamic wr = CLRLoader.CLRFrameworkLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRFrameworWrapperClassName))
#endif
            {
                wr.IsDebug = false;

                var coreSignatureContext = signatureContext.ConvertSignatureContext();
                var coreResult = wr.CAdESSign(dataToSign, coreSignatureContext);

                result = DataConversion.ConvertAdESResult(coreResult);
            }
            return result;
        }

        public Task<AdESResult> CAdESSignAsync(byte[] dataToSign, SignatureContext signatureContext)
        {
            return Task.FromResult(CAdESSign(dataToSign, signatureContext));
        }

        public AdESResult PAdESSign(byte[] dataToSign, PAdESSignatureContext signatureContext)
        {
            AdESResult result;
#if NET5_0
            using (dynamic wr = CLRLoader.CLRLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRWrapperClassName))
#else
            using (dynamic wr = CLRLoader.CLRFrameworkLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRFrameworWrapperClassName))
#endif
            {
                wr.IsDebug = false;
                
                var coreSignatureContext = signatureContext.ConvertPAdESSignatureContext();
                var coreResult = wr.PAdESSign(dataToSign, coreSignatureContext);

                result = DataConversion.ConvertAdESResult(coreResult);
            }
            return result;
        }

        public Task<AdESResult> PAdESSignAsync(byte[] dataToSign, PAdESSignatureContext signatureContext)
        {
            return Task.FromResult(PAdESSign(dataToSign, signatureContext));
        }

        public AdESResult XAdESSign(byte[] dataToSign, XAdESSignatureContext signatureContext)
        {
            AdESResult result;
#if NET5_0
            using (dynamic wr = CLRLoader.CLRLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRWrapperClassName))
#else
            using (dynamic wr = CLRLoader.CLRFrameworkLibrary
                .CreateCLRInstance(BaseConstants.AdESCLRFrameworWrapperClassName))
#endif
            {
                wr.IsDebug = false;

                var coreSignatureContext = signatureContext.ConvertXAdESSignatureContext();
                var coreResult = wr.XAdESSign(dataToSign, coreSignatureContext);

                result = DataConversion.ConvertAdESResult(coreResult);
            }
            return result;
        }

        public Task<AdESResult> XAdESSignAsync(byte[] dataToSign, XAdESSignatureContext signatureContext)
        {
            return Task.FromResult(XAdESSign(dataToSign, signatureContext));
        }
    }
}
