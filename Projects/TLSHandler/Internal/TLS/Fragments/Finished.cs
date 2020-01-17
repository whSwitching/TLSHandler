using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.9
    //https://tools.ietf.org/html/rfc8446#section-4.4.4
    public class Finished : FragmentBody
    {
        public byte[] VerifyData { get; private set; }
        public byte[] Mac { get; private set; }

        public Finished(byte[] bodyBytes, int verifyLen=12) : base(bodyBytes)
        {
            VerifyData = Data.Take(verifyLen).ToArray();
            Mac = Data.Skip(verifyLen).ToArray();
        }
    }
}
