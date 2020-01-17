using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Records
{
    public abstract class TLSRecord : PacketData
    {
        public RecordType Type { get { return (RecordType)Data[0]; } }
        public ProtocolVersion Version { get { return (ProtocolVersion)Utils.ToUInt16(Data, 1); } }
        public ushort PayloadLength { get { return Utils.ToUInt16(Data, 3); } }
        public byte[] Payload { get { return Data.Skip(5).ToArray(); } }

        protected TLSRecord(RecordType type, ProtocolVersion ver, byte[] payload)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                ms.WriteByte((byte)type);
                ms.WriteValue((ushort)ver);
                ms.WriteValue(payload, Utils.UInt16Bytes((ushort)payload.Length));
                Data = ms.ToArray();
            }
        }

        public byte[] GetHeaderBytes()
        {
            return Data.Take(5).ToArray();
        }

        public static TLSRecord[] Extract(byte[] recordsBytes)
        {
            var records = new List<TLSRecord>();

            int idx = 0;
            while (idx < recordsBytes.Length)
            {
                var type = (RecordType)recordsBytes[idx];
                var ver = (ProtocolVersion)Utils.ToUInt16(recordsBytes, idx + 1);
                var length = Utils.ToUInt16(recordsBytes, idx + 3);
                idx += 5;

                var buffer = new byte[length];
                Buffer.BlockCopy(recordsBytes, idx, buffer, 0, buffer.Length);
                records.Add(Factory(type, ver, buffer));

                idx += length;
            }

            return records.ToArray();
        }

        public static TLSRecord Factory(RecordType type, ProtocolVersion ver, byte[] payload)
        {
            if (type == RecordType.Alert)
                return new Alert(payload);
            else if (type == RecordType.ApplicationData)
                return new ApplicationData(payload);
            else if (type == RecordType.ChangeCipherSpec)
                return new ChangeCipherSpec(payload);
            else if (type == RecordType.Handshake)
                return new Handshake(payload);
            else
                throw new FormatException($"Invalid RecordType {type}");
        }
    }
}
