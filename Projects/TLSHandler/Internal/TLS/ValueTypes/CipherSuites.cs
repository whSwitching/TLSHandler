using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.ValueTypes
{
    public class CipherSuites : PacketData
    {
        public CipherSuite[] Ciphers { get; private set; }

        public CipherSuites(CipherSuite[] ciphers)
        {
            this.Ciphers = ciphers;

            var ciphersByteLen = (ushort)(this.Ciphers.Length * 2);
            var lenBytes = Utils.UInt16Bytes(ciphersByteLen);
            Data = new byte[2 + ciphersByteLen];
            Data[0] = lenBytes[0];
            Data[1] = lenBytes[1];
            for (int i = 0; i < this.Ciphers.Length; i++)
            {
                var cipher = Utils.UInt16Bytes((ushort)this.Ciphers[i]);
                Data[2 + i * 2] = cipher[0];
                Data[3 + i * 2] = cipher[1];
            }
        }
    }
}
