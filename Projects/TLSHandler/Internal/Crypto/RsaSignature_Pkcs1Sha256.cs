using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Crypto
{
    class RsaSignature_Pkcs1Sha256 : RsaSignature
    {
        public override SignatureAlgorithm Algorithm { get { return SignatureAlgorithm.rsa_pkcs1_sha256; } }
        public override HashAlgorithmName HashName { get { return HashAlgorithmName.SHA256; } }
        public override RSASignaturePadding Padding { get { return RSASignaturePadding.Pkcs1; } }

        public override byte[] Hash(byte[] data)
        {
            using (var sha = new SHA256Cng())
            {
                return sha.ComputeHash(data);
            }
        }
    }
}
