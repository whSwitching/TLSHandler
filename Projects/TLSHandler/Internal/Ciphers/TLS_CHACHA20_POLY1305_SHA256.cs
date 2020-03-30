using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Ciphers
{
    class TLS_CHACHA20_POLY1305_SHA256 : Suite13<BulkEncryption.ChaCha20_Poly1305, HMACSHA256, SHA256Cng>
    {
        public override CipherSuite CipherSuite => CipherSuite.TLS_CHACHA20_POLY1305_SHA256;

        protected override BulkEncryption.ChaCha20_Poly1305 GetBulkEncryption()
        {
            return new BulkEncryption.ChaCha20_Poly1305();
        }

        protected override HMAC GetHmacFunction()
        {
            return new HMACSHA256();
        }

        public override HashAlgorithm GetHashAlgorithm()
        {
            return new SHA256Cng();
        }
    }
}
