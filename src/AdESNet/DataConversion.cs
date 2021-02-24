using System.Reflection;
using AdESNet.Common;
using AutoMapper;

namespace AdESNet
{
    public static class DataConversion
    {
        static readonly IMapper AutoMapper;
        static readonly Assembly Assembly;

        static DataConversion()
        {
#if NET5_0
            Assembly = CLRLoader.CLRLibrary;
#else
            Assembly = CLRLoader.CLRFrameworkLibrary;
#endif
            var config = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<BaseClassesProfile>();
            });

            AutoMapper = config.CreateMapper();
        }

        public static dynamic ConvertSignatureContext(this SignatureContext signatureContext)
        {
            return AutoMapper.Map(signatureContext, typeof(SignatureContext), Assembly.GetType(BaseConstants.SignatureContextClassName));
        }

        public static dynamic ConvertPAdESSignatureContext(this PAdESSignatureContext pAdESSignatureContext)
        {
            return AutoMapper.Map(pAdESSignatureContext, typeof(PAdESSignatureContext), Assembly.GetType(BaseConstants.PAdESSignatureContextClassName));
        }

        public static dynamic ConvertXAdESSignatureContext(this XAdESSignatureContext xAdESSignatureContext)
        {
            return AutoMapper.Map(xAdESSignatureContext, typeof(XAdESSignatureContext), Assembly.GetType(BaseConstants.XAdESSignatureContextClassName));
        }

        public static AdESResult ConvertAdESResult(dynamic adEsResult)
        {
#if NET5_0
            return AutoMapper.Map<AdESResult>(adEsResult);
#else
            return new AdESResult
            {
                Status = adEsResult.Status,
                Error = adEsResult.Error,
                signedData = adEsResult.signedData
            };
#endif
        }
    }
}
