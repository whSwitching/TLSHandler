using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.KeyExchange
{
    //https://tools.ietf.org/html/rfc5246#section-8.1.1
    class RsaKeyExchange : KeyExchange12
    {
        public override bool IsRsaKeyExchange { get { return true; } }
        public RsaKeyExchange(int handshakeKeyLen, int applicationKeyLen) : base(handshakeKeyLen, applicationKeyLen)
        {
        }

        protected override void GenerateMasterSecret(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters)
        {
            var pre_master = Utils.RSA_Decrypt(encryptedPreMasterSecret, (RSAParameters)privateParameters);

            MasterSecret = RandomFunction.PRF.GetBytes_HMACSHA256(pre_master, "master secret", clientRandom.Concat(serverRandom).ToArray(), 48);
        }

    }
}
