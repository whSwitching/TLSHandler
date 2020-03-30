using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc8446#section-4.3.1
    class EncryptedExtensions : FragmentBody
    {
        public EncryptedExtensions() : base(null)
        {
            Data = new byte[] { 0x00, 0x00 };
        }
    }
}
