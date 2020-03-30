using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.ValueTypes
{
    class CompressionMethods : PacketData
    {
        public CompressionMethod[] Methods { get; private set; }

        public CompressionMethods(CompressionMethod[] methods)
        {
            if (methods == null || methods.Length == 0)
            {
                Data = new byte[] { 0x00 };
            }
            else
            {
                Methods = methods;

                Data = new byte[1 + methods.Length];
                Data[0] = (byte)methods.Length;
                for (int i = 0; i < methods.Length; i++)
                {
                    Data[1 + i] = (byte)methods[i];
                }
            }
        }
    }
}
