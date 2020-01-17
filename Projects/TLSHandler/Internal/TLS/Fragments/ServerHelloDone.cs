using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.5
    public class ServerHelloDone : FragmentBody
    {
        public ServerHelloDone() : base(new byte[0])
        {
        }
    }
}
