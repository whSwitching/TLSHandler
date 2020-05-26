using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    class TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA : Suite12<KeyExchange.EcdheKeyExchange, BulkEncryption.Aes128_CBC, HMACSHA1>
    {
        public override Enums.CipherSuite CipherSuite => Enums.CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;


        protected override KeyExchange.EcdheKeyExchange GetKeyExchange()
        {
            return new KeyExchange.EcdheKeyExchange(20, 16);
        }

        protected override BulkEncryption.Aes128_CBC GetBulkEncryption()
        {
            return new BulkEncryption.Aes128_CBC();
        }

        protected override HMAC GetHmacFunction()
        {
            return new HMACSHA1();
        }
    }
}
