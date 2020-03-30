using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    class TLS_RSA_WITH_AES_128_CBC_SHA256 : Suite12<KeyExchange.RsaKeyExchange, BulkEncryption.Aes128_CBC, HMACSHA256>
    {
        public override Enums.CipherSuite CipherSuite => Enums.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256;


        protected override KeyExchange.RsaKeyExchange GetKeyExchange()
        {
            return new KeyExchange.RsaKeyExchange(32, 16);
        }
        
        protected override BulkEncryption.Aes128_CBC GetBulkEncryption()
        {
            return new BulkEncryption.Aes128_CBC();
        }

        protected override HMAC GetHmacFunction()
        {
            return new HMACSHA256();
        }
    }
}
