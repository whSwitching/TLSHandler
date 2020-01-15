using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc4492#section-5.4
    public enum ECCurveType : byte
    {
        explicit_prime = 1,
        explicit_char2 = 2,
        named_curve = 3,
        //reserved (248..255)
    }
}
