using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    public abstract class FragmentBody : PacketData
    {
        protected FragmentBody(byte[] bodyBytes)
        {
            Data = bodyBytes;
        }

        public static FragmentBody Factory(HandshakeType type, byte[] bodyBytes)
        {
            if (type == HandshakeType.Client_Hello)
            {
                return new ClientHello(bodyBytes);
            }
            else if (type == HandshakeType.Certificate)
            {
                return new Certificate(bodyBytes);
            }            
            else if (type == HandshakeType.Client_Key_Exchange)
            {
                return new ClientKeyExchange(bodyBytes);
            }
            else if (type == HandshakeType.Certificate_Verify)
            {
                return new CertificateVerify(bodyBytes);
            }
            else if (type == HandshakeType.Finished)
            {
                return new Finished(bodyBytes);
            }

            throw new Exception($"unhandled HandshakeType {type}");
        }
    }
}
