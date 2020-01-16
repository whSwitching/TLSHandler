using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Crypto
{
    class RsaSignature_PssRsaeSha384 : RsaSignature
    {
        public override SignatureAlgorithm Algorithm { get { return SignatureAlgorithm.rsa_pss_rsae_sha384; } }
        public override HashAlgorithmName HashName { get { return HashAlgorithmName.SHA384; } }
        public override RSASignaturePadding Padding { get { return RSASignaturePadding.Pss; } }

        public override byte[] Hash(byte[] data)
        {
            using (var sha = new SHA384Cng())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}
