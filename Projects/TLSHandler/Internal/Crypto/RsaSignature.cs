using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Crypto
{
    abstract class RsaSignature : ISignature
    {
        public abstract SignatureAlgorithm Algorithm { get; }
        public abstract HashAlgorithmName HashName { get; }
        public abstract RSASignaturePadding Padding { get; }

        public abstract byte[] Hash(byte[] data);

        public byte[] Sign(byte[] data, object rsaPrivateParameters)
        {
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters((RSAParameters)rsaPrivateParameters);

                return rsa.SignData(data, HashName, Padding);
            }
        }
    }
}
