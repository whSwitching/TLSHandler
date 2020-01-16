using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Crypto
{
    class RsaSignature_PssRsaeSha512 : RsaSignature
    {
        public override SignatureAlgorithm Algorithm { get { return SignatureAlgorithm.rsa_pss_rsae_sha512; } }
        public override HashAlgorithmName HashName { get { return HashAlgorithmName.SHA512; } }
        public override RSASignaturePadding Padding { get { return RSASignaturePadding.Pss; } }

        public override byte[] Hash(byte[] data)
        {
            using (var sha = new SHA512Cng())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}
