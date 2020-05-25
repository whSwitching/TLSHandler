using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.4
    //https://tools.ietf.org/html/rfc8446#section-4.3.2
    class CertificateRequest : FragmentBody
    {
        public ClientCertificateType[] CertificateTypes { get; private set; }
        public SignatureAlgorithm[] SignatureAlgorithms { get; private set; }
        /* TLS 1.2
        01 01 // CertificateTypes
        00 0C // SignatureAlgorithms len
        04 01 05 01 06 01 08 04 08 05 08 06 // SignatureAlgorithms
        00 00 // opaque DistinguishedName
        */
        public CertificateRequest(ClientCertificateType[] clientCertTypes = null, SignatureAlgorithm[] clientCertSAs = null) : base(null)
        {
            CertificateTypes = clientCertTypes ?? new[]
            {
                ClientCertificateType.rsa_sign,
            };
            SignatureAlgorithms = clientCertSAs ?? new[]
            {
                SignatureAlgorithm.rsa_pkcs1_sha256, SignatureAlgorithm.rsa_pkcs1_sha384, SignatureAlgorithm.rsa_pkcs1_sha512,
                SignatureAlgorithm.rsa_pss_rsae_sha256, SignatureAlgorithm.rsa_pss_rsae_sha384, SignatureAlgorithm.rsa_pss_rsae_sha512,
                SignatureAlgorithm.ecdsa_secp256r1_sha256, SignatureAlgorithm.ecdsa_secp384r1_sha384, SignatureAlgorithm.ecdsa_secp521r1_sha512,
            };
            using (var ms = new System.IO.MemoryStream())
            {
                // ClientCertificateTypes length byte
                ms.WriteByte((byte)CertificateTypes.Length);
                // ClientCertificateTypes
                ms.Write(CertificateTypes.Select(a => (byte)a).ToArray(), 0, CertificateTypes.Length);
                // SignatureAlgorithms length ushort
                ms.WriteValue((ushort)(SignatureAlgorithms.Length * 2));
                // SignatureAlgorithms
                foreach (var sa in SignatureAlgorithms)
                    ms.WriteValue((ushort)(sa));
                //DistinguishedName
                ms.WriteValue((ushort)0);

                Data = ms.ToArray();
            }
        }
        /* TLS 1.3
        00 // opaque certificate_request_context
        00 2a // extension len
        00 0d 00 26 // SignatureAlgorithm extension len
        00 24 // SignatureAlgorithms len
        04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03 02 03 03 01 02 01
        */        
        public CertificateRequest(byte[] cert_request_context, SignatureAlgorithm[] clientCertSAs = null) : base(null)
        {
            //https://tools.ietf.org/html/rfc8446#page-70
            //In addition, the signature algorithm MUST be compatible with the key in the sender's end-entity certificate.
            //RSA signatures MUST use an RSASSA - PSS algorithm, regardless of whether RSASSA-PKCS1 - v1_5 algorithms appear in "signature_algorithms".
            //The SHA - 1 algorithm MUST NOT be used in any signatures of CertificateVerify messages.
            CertificateTypes = new ClientCertificateType[0];
            SignatureAlgorithms = clientCertSAs ?? new[]
            {
                SignatureAlgorithm.rsa_pss_rsae_sha256, SignatureAlgorithm.rsa_pss_rsae_sha384, SignatureAlgorithm.rsa_pss_rsae_sha512,
                SignatureAlgorithm.ecdsa_secp256r1_sha256, SignatureAlgorithm.ecdsa_secp384r1_sha384, SignatureAlgorithm.ecdsa_secp521r1_sha512,
            };

            var extBytes = new Extensions.SignatureAlgorithms(SignatureAlgorithms).Data;
            using (var ms = new System.IO.MemoryStream())
            {
                // certificate_request_context
                if (cert_request_context != null && cert_request_context.Length > 0)
                    ms.WriteValue(cert_request_context, new[] { (byte)cert_request_context.Length });
                else
                    ms.WriteByte((byte)0);
                // Extensions total length ushort
                ms.WriteValue((ushort)(extBytes.Length));
                // SignatureAlgorithms Extension
                ms.Write(extBytes, 0, extBytes.Length);

                Data = ms.ToArray();
            }
        }
    }
}
