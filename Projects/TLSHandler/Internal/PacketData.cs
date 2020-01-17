using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    public abstract class PacketData
    {
        public byte[] Data { get; protected set; }
    }
}
