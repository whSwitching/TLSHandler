using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Crypto
{
    class RsaSignature_PssRsaeSha256 : RsaSignature
    {
        public override SignatureAlgorithm Algorithm { get { return SignatureAlgorithm.rsa_pss_rsae_sha256; } }
        public override HashAlgorithmName HashName { get { return HashAlgorithmName.SHA256; } }
        public override RSASignaturePadding Padding { get { return RSASignaturePadding.Pss; } }

        public override byte[] Hash(byte[] data)
        {
            using (var sha = new SHA256Cng())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}
