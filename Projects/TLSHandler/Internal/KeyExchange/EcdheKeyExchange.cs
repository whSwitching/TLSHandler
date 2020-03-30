using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Parameters = Org.BouncyCastle.Crypto.Parameters;
using TlsEccUtilities = Org.BouncyCastle.Crypto.Tls.TlsEccUtilities;

namespace TLSHandler.Internal.KeyExchange
{
    //https://tools.ietf.org/html/rfc5246#section-8.1.2
    class EcdheKeyExchange : KeyExchange12
    {
        public override bool IsRsaKeyExchange { get { return false; } }
        public EcdheKeyExchange(int handshakeKeyLen, int applicationKeyLen) : base(handshakeKeyLen, applicationKeyLen)
        {
        }

        protected override void GenerateMasterSecret(byte[] clientEcdhPubkey, byte[] clientRandom, byte[] serverRandom, object privateParameters)
        {
            var pre_master = new byte[32];
            if (privateParameters is Parameters.X25519PrivateKeyParameters x25519Prv)
            {
                var clientPub = new Parameters.X25519PublicKeyParameters(clientEcdhPubkey, 0);
                x25519Prv.GenerateSecret(clientPub, pre_master, 0);
            }
            else if (privateParameters is Parameters.X448PrivateKeyParameters x448Prv)
            {
                var clientPub = new Parameters.X448PublicKeyParameters(clientEcdhPubkey, 0);
                x448Prv.GenerateSecret(clientPub, pre_master, 0);
            }
            else if (privateParameters is Parameters.ECPrivateKeyParameters serverPrv)
            {
                var ecDomainParam = serverPrv.Parameters;
                var clientQ = TlsEccUtilities.DeserializeECPoint(new byte[] { 0x04 }, ecDomainParam.Curve, clientEcdhPubkey);
                var clientPub = new Parameters.ECPublicKeyParameters(clientQ, ecDomainParam);
                pre_master = TlsEccUtilities.CalculateECDHBasicAgreement(clientPub, serverPrv);
            }

            MasterSecret = RandomFunction.PRF.GetBytes_HMACSHA256(pre_master, "master secret", clientRandom.Concat(serverRandom).ToArray(), 48);
        }

    }
}
