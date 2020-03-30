using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    // Mandatory Cipher Suite in TLS1.2  https://tools.ietf.org/html/rfc5246#section-9
    class TLS_RSA_WITH_AES_128_CBC_SHA : Suite12<KeyExchange.RsaKeyExchange, BulkEncryption.Aes128_CBC, HMACSHA1>
    {
        public override Enums.CipherSuite CipherSuite => Enums.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;


        protected override KeyExchange.RsaKeyExchange GetKeyExchange()
        {
            return new KeyExchange.RsaKeyExchange(20, 16);
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
