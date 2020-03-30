using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Handshakes
{
    class Fragment : PacketData
    {
        public virtual HandshakeType MessageType { get { return (HandshakeType)Data[0]; } }
        public virtual uint BodyLength { get { return Utils.ToUInt24(Data, 1); } }
        public virtual Fragments.FragmentBody Body { get; private set; }


        public Fragment(HandshakeType type, Fragments.FragmentBody body)
        {
            var bodyBytes = body.Data;
            var length = bodyBytes.Length;
            var lengthBytes = Utils.UInt24Bytes((uint)length);
            Data = new byte[4 + length];
            Data[0] = (byte)type;
            Buffer.BlockCopy(lengthBytes, 0, Data, 1, 3);
            Buffer.BlockCopy(bodyBytes, 0, Data, 4, length);
            Body = body;
        }

        public Fragment(byte[] fragmentBytes)
        {
            Data = fragmentBytes;
            Body = Fragments.FragmentBody.Factory(MessageType, Data.Skip(4).ToArray());
        }
    }
}
