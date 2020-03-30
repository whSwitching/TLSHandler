using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Ciphers
{
    class TLS_AES_256_GCM_SHA384 : Suite13<BulkEncryption.Aes256_GCM, HMACSHA384, SHA384Cng>
    {
        public override CipherSuite CipherSuite => CipherSuite.TLS_AES_256_GCM_SHA384;

        protected override BulkEncryption.Aes256_GCM GetBulkEncryption()
        {
            return new BulkEncryption.Aes256_GCM();
        }

        protected override HMAC GetHmacFunction()
        {
            return new HMACSHA384();
        }

        public override HashAlgorithm GetHashAlgorithm()
        {
            return new SHA384Cng();
        }
    }
}
