using AdESNet.Common;
using AutoMapper;

namespace AdESNet
{
    public class BaseClassesProfile : Profile
    {
        public BaseClassesProfile()
        {
#if NET5_0
            var assembly = CLRLoader.CLRLibrary;
#else
            var assembly = CLRLoader.CLRFrameworkLibrary;
#endif

            CreateMap(assembly.GetType(BaseConstants.CertificateIdentifierClassName), typeof(CertificateIdentifier));
            CreateMap(typeof(CertificateIdentifier), assembly.GetType(BaseConstants.CertificateIdentifierClassName));

            CreateMap(assembly.GetType(BaseConstants.AdESAttributesClassName), typeof(AdESAttributes));
            CreateMap(typeof(AdESAttributes), assembly.GetType(BaseConstants.AdESAttributesClassName));

            CreateMap(assembly.GetType(BaseConstants.SignerAttributesClassName), typeof(SignerAttributes));
            CreateMap(typeof(SignerAttributes), assembly.GetType(BaseConstants.SignerAttributesClassName));

            CreateMap(assembly.GetType(BaseConstants.TsaProfilClassName), typeof(TsaProfil));
            CreateMap(typeof(TsaProfil), assembly.GetType(BaseConstants.TsaProfilClassName));

            CreateMap(assembly.GetType(BaseConstants.SignatureContextClassName), typeof(SignatureContext));
            CreateMap(typeof(SignatureContext), assembly.GetType(BaseConstants.SignatureContextClassName));

            CreateMap(assembly.GetType(BaseConstants.PAdESSpecificAttributesClassName), typeof(PAdESSpecificAttributes));
            CreateMap(typeof(PAdESSpecificAttributes), assembly.GetType(BaseConstants.PAdESSpecificAttributesClassName));

            CreateMap(assembly.GetType(BaseConstants.PAdESSignatureContextClassName), typeof(PAdESSignatureContext));
            CreateMap(typeof(PAdESSignatureContext), assembly.GetType(BaseConstants.PAdESSignatureContextClassName));

            CreateMap(assembly.GetType(BaseConstants.XAdESSpecificAttributesClassName), typeof(XAdESSpecificAttributes));
            CreateMap(typeof(XAdESSpecificAttributes), assembly.GetType(BaseConstants.XAdESSpecificAttributesClassName));

            CreateMap(assembly.GetType(BaseConstants.XAdESSignatureContextClassName), typeof(XAdESSignatureContext));
            CreateMap(typeof(XAdESSignatureContext), assembly.GetType(BaseConstants.XAdESSignatureContextClassName));

            CreateMap(assembly.GetType(BaseConstants.AdESResultClassName), typeof(AdESResult));
            CreateMap(typeof(AdESResult), assembly.GetType(BaseConstants.AdESResultClassName));
        }
    }
}
