using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Records
{
    public class Handshake : TLSRecord
    {
        public PacketData[] Fragments { get; private set; }

        public Handshake(byte[] payload) : base(RecordType.Handshake, ProtocolVersion.TLSv1_2, payload)
        {
            Fragments = ExtractFragments(payload);
        }

        public Handshake(PacketData[] fragments) : base(RecordType.Handshake, ProtocolVersion.TLSv1_2, Utils.GetPayloadData(fragments))
        {
            Fragments = fragments;
        }

        PacketData[] ExtractFragments(byte[] payload)
        {
            var ret = new List<PacketData>();

            var offset = 0;
            while (offset < payload.Length)
            {
                var type = (HandshakeType)payload[offset];
                var length = (int)Utils.ToUInt24(payload, offset + 1);

                if (Enum.IsDefined(typeof(HandshakeType), type) && offset + 4 + length <= payload.Length)
                {
                    var body = payload.Skip(offset + 4).Take(length).ToArray();
                    ret.Add(new Handshakes.Fragment(type, TLS.Fragments.FragmentBody.Factory(type, body)));
                    offset += 4;
                    offset += length;
                }
                else//if (!Enum.IsDefined(typeof(HandshakeType), type) && offset + 4 + length != this.Payload.Length)
                {
                    var body = payload.Skip(offset).ToArray();
                    ret.Add(new Handshakes.EncryptedFragment(body));
                    offset += body.Length;
                }
            }

            return ret.ToArray();
        }
    }
}
