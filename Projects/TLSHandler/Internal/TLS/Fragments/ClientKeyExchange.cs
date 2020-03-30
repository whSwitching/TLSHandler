using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.7
    class ClientKeyExchange : FragmentBody
    {
        // for RSA
        public ushort RSA_PreMasterSecretLength { get { return Utils.ToUInt16(Data, 0); } }
        public byte[] RSA_PreMasterSecret { get { return Data.Skip(2).ToArray(); } }
        // for ECDH
        public byte ECDH_PubkeyLength { get { return Data[0]; } }
        public byte[] ECDH_Pubkey { get { return Data.Skip(1).Take(ECDH_PubkeyLength).ToArray(); } }
        //public byte[] ECDH_PubkeyX { get { return data.Skip(2).Take(32).ToArray(); } }
        //public byte[] ECDH_PubkeyY { get { return data.Skip(2+32).Take(32).ToArray(); } }

        public ClientKeyExchange(byte[] bodyBytes) : base(bodyBytes)
        {
        }
    }
}
