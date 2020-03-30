using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Handshakes
{
    class EncryptedFragment : PacketData
    {
        public byte[] IV { get { return Data.Take(16).ToArray(); } }
        public byte[] EncryptedData { get { return Data.Skip(16).ToArray(); } }

        public EncryptedFragment(byte[] bodyBytes)
        {
            Data = bodyBytes;
        }
    }
}
