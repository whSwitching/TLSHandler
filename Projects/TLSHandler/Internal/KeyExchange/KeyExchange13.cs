using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Parameters = Org.BouncyCastle.Crypto.Parameters;
using TlsEccUtilities = Org.BouncyCastle.Crypto.Tls.TlsEccUtilities;

namespace TLSHandler.Internal.KeyExchange
{
    class KeyExchange13 : IKeyExchange
    {
        public bool IsRsaKeyExchange { get { return false; } }
        public byte[] SharedSecret { get; protected set; } = new byte[48];

        public virtual void Exchange(byte[] clientEcdhPubkey, byte[] cRandomUnused, byte[] sRandomUnused, object privateParameters)
        {
            // "TLS1.3 ciphersuite does not include KeyExchange methods"
            // just for shared_secret calculation here
            var shared_secret = new byte[32];
            if (privateParameters is Parameters.X25519PrivateKeyParameters x25519Prv)
            {
                var clientPub = new Parameters.X25519PublicKeyParameters(clientEcdhPubkey, 0);
                x25519Prv.GenerateSecret(clientPub, shared_secret, 0);
            }
            else if (privateParameters is Parameters.X448PrivateKeyParameters x448Prv)
            {
                var clientPub = new Parameters.X448PublicKeyParameters(clientEcdhPubkey, 0);
                x448Prv.GenerateSecret(clientPub, shared_secret, 0);
            }
            else if (privateParameters is Parameters.ECPrivateKeyParameters serverPrv)
            {
                var ecDomainParam = serverPrv.Parameters;
                var clientQ = TlsEccUtilities.DeserializeECPoint(new byte[] { 0x04 }, ecDomainParam.Curve, clientEcdhPubkey);
                var clientPub = new Parameters.ECPublicKeyParameters(clientQ, ecDomainParam);
                shared_secret = TlsEccUtilities.CalculateECDHBasicAgreement(clientPub, serverPrv);
            }
            else
            {
                throw new NotSupportedException("Unsupported KeyShare Group");
            }
            SharedSecret = shared_secret;
        }

        public void Dispose()
        {
            Utils.EmptyBuffer(SharedSecret);
        }
    }
}
