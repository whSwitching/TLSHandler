using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc8422#section-5.1.2
    public enum ECPointFormat : byte
    {
        Uncompressed = 0,
        Deprecated1 = 1,
        Deprecated2 = 2,
        //reserved (248..255)
    }
}
