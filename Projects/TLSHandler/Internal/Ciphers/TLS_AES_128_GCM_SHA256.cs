using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Ciphers
{
    // Mandatory Cipher Suite in TLS1.3  https://tools.ietf.org/html/rfc8446#section-9.1
    class TLS_AES_128_GCM_SHA256 : Suite13<BulkEncryption.Aes128_GCM, HMACSHA256, SHA256Cng>
    {
        public override CipherSuite CipherSuite => CipherSuite.TLS_AES_128_GCM_SHA256;

        protected override BulkEncryption.Aes128_GCM GetBulkEncryption()
        {
            return new BulkEncryption.Aes128_GCM();
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
