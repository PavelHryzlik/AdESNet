using System;
using System.Runtime.InteropServices;

namespace AdESNet.ConsoleTest
{
    public class Crypto32
    {
        #region CONSTS

        // #define CERT_COMPARE_SHIFT        16
        public const Int32 CERT_COMPARE_SHIFT = 16;

        // #define CERT_STORE_PROV_SYSTEM_W      ((LPCSTR) 10)
        public const Int32 CERT_STORE_PROV_SYSTEM_W = 10;

        // #define CERT_STORE_PROV_SYSTEM        CERT_STORE_PROV_SYSTEM_W
        public const Int32 CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;

        // #define CERT_SYSTEM_STORE_CURRENT_USER_ID     1
        public const Int32 CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;

        // #define CERT_SYSTEM_STORE_LOCATION_SHIFT      16
        public const Int32 CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;

        // #define CERT_SYSTEM_STORE_CURRENT_USER        \
        //   (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
        public const Int32 CERT_SYSTEM_STORE_CURRENT_USER =
            CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

        // #define CERT_COMPARE_SHA1_HASH      1
        public const Int32 CERT_COMPARE_SHA1_HASH = 1;

        // #define CERT_FIND_SHA1_HASH     (CERT_COMPARE_SHA1_HASH << CERT_COMPARE_SHIFT)
        public const Int32 CERT_FIND_SHA1_HASH = (CERT_COMPARE_SHA1_HASH << CERT_COMPARE_SHIFT);

        public const uint CERT_FIND_SUBJECT_STR = 0x00080007;

        // #define X509_ASN_ENCODING           0x00000001
        public const Int32 X509_ASN_ENCODING = 0x00000001;

        // #define PKCS_7_ASN_ENCODING         0x00010000
        public const Int32 PKCS_7_ASN_ENCODING = 0x00010000;

        // #define MY_TYPE       (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
        public const Int32 MY_ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

        #endregion

        #region STRUCTS

        // typedef struct _CRYPTOAPI_BLOB 
        // {
        //      DWORD   cbData;
        //      BYTE    *pbData;
        // } CRYPT_HASH_BLOB, CRYPT_INTEGER_BLOB, 
        //   CRYPT_OBJID_BLOB, CERT_NAME_BLOB;
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTOAPI_BLOB
        {
            public Int32 cbData;
            public IntPtr pbData;
        }

        #endregion

        #region FUNCTIONS (IMPORTS)

        // HCERTSTORE WINAPI CertOpenStore(
        //      LPCSTR lpszStoreProvider,
        //      DWORD dwMsgAndCertEncodingType,
        //      HCRYPTPROV hCryptProv,
        //      DWORD dwFlags,
        //      const void* pvPara
        // );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenStore(
            uint lpszStoreProvider,
            uint dwMsgAndCertEncodingType,
            IntPtr hCryptProv,
            uint dwFlags,
            String pvPara
        );

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenSystemStore(
            IntPtr hCryptProv,
            string storename);

        // BOOL WINAPI CertCloseStore(
        //      HCERTSTORE hCertStore,
        //      DWORD dwFlags
        // );
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(
            IntPtr hCertStore,
            uint dwFlags);

        // PCCERT_CONTEXT WINAPI CertFindCertificateInStore(
        //      HCERTSTORE hCertStore,
        //      DWORD dwCertEncodingType,
        //      DWORD dwFindFlags,
        //      DWORD dwFindType,
        //      const void* pvFindPara,
        //      PCCERT_CONTEXT pPrevCertContext
        // );
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(
            IntPtr hCertStore,
            uint dwCertEncodingType,
            uint dwFindFlags,
            uint dwFindType,
            IntPtr pvFindPara,
            IntPtr pPrevCertCntxt);


        // BOOL WINAPI CertFreeCertificateContext(
        //      PCCERT_CONTEXT pCertContext
        // );
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern Boolean CertFreeCertificateContext(
            IntPtr pCertContext
        );

        #endregion
    }
}
