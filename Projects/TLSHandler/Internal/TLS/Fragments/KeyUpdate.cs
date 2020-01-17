using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc8446#section-4.6.3
    public class KeyUpdate : FragmentBody
    {
        public KeyUpdateRequest Request { get { return (KeyUpdateRequest)Data[0]; } }

        public KeyUpdate(byte[] bodyBytes) : base(bodyBytes)
        {
        }

        public KeyUpdate(KeyUpdateRequest req) : base(new byte[] { (byte)req })
        {
        }
    }
}
