using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc8446#section-4.6.3
    public enum KeyUpdateRequest : byte
    {
        Update_Not_Requested = 0,
        Update_Requested = 1,
    }
}
