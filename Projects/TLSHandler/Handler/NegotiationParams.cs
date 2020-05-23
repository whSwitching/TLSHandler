using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;
using TLS = TLSHandler.Internal.TLS;
using Ciphers = TLSHandler.Internal.Ciphers;

namespace TLSHandler.Handler
{
    class NegotiationParams
    {
        public bool ServerNameCheck { get; private set; }   //SNI check
        public bool ClientCertificateRequire { get; private set; }
        public bool EnableTls13 { get; private set; }

        public TLS.ValueTypes.Random ClientRandom { get; set; }
        public TLS.ValueTypes.Random ServerRandom { get; set; }
        public TLS.ValueTypes.Session Session { get; set; } // session id in clienthello
        public NamedGroup KeyExchangeCurve { get; set; }
        public SignatureAlgorithm SignatureAlgorithm { get; set; }
        public Ciphers.CipherSuiteBase Cipher { get; set; }
        public Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair ServerKey { get; set; }

        public TLS.Extensions.KeyShareEntry KeyShare { get; set; }
        public TLS.Extensions.ClientOfferedPsks PSK { get; set; }

        public NegotiationParams(bool clientCertRequire = false, bool forceServerNameCheck = false, bool enableTls13 = true)
        {
            ClientCertificateRequire = clientCertRequire;
            ServerNameCheck = forceServerNameCheck;
            EnableTls13 = enableTls13;
        }
    }
}
