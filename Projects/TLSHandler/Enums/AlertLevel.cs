using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc5246#section-7.2
    public enum AlertLevel : byte
    {
        Warning = 1,
        Fatal = 2,
    }
}
