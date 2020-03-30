using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.ValueTypes
{
    class Session : PacketData
    {
        public byte[] ID { get; private set; }

        public Session(Guid id) : this(id.ToByteArray())
        {
        }

        public Session(byte[] id)
        {
            this.ID = id;

            var idLen = this.ID == null ? (byte)0 : (byte)ID.Length;
            Data = new byte[1 + idLen];
            Data[0] = idLen;
            if (ID != null)
                Buffer.BlockCopy(ID, 0, Data, 1, ID.Length);
        }

    }
}
