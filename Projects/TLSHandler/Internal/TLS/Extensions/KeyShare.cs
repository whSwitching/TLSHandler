using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.8
    class KeyShare : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.KEY_SHARE; } }

        public ushort EntriesLength { get { return Utils.ToUInt16(Data, 4); } }

        public KeyShareEntry[] Entries { get; private set; }

        public KeyShare(byte[] extensionBytes) : base(extensionBytes)
        {
            var entriesBytes = Data.Skip(6).ToArray();
            Entries = KeyShareEntry.ExtractEntries(entriesBytes);
        }

        public KeyShare(NamedGroup group, byte[] keyexchange) : base(null)
        {
            Entries = new[] { new KeyShareEntry(group, keyexchange) };

            var entriesBytes = new List<byte>();
            foreach (var entry in Entries)
                entriesBytes.AddRange(entry.Data);

            Data = new byte[2 + 2 + entriesBytes.Count];
            var bytesType = Utils.UInt16Bytes((ushort)Type);
            var bytesLen = Utils.UInt16Bytes((ushort)entriesBytes.Count);
            Buffer.BlockCopy(bytesType, 0, Data, 0, 2);
            Buffer.BlockCopy(bytesLen, 0, Data, 2, 2);
            Buffer.BlockCopy(entriesBytes.ToArray(), 0, Data, 4, entriesBytes.Count);
        }
    }

    public class KeyShareEntry : PacketData
    {
        public NamedGroup Group { get; set; }
        public byte[] KeyExchange { get; set; }

        public KeyShareEntry(NamedGroup group, byte[] key)
        {
            Group = group;
            KeyExchange = key;

            Data = new byte[KeyExchange.Length + 4];
            Buffer.BlockCopy(Utils.UInt16Bytes((ushort)Group), 0, Data, 0, 2);
            Buffer.BlockCopy(Utils.UInt16Bytes((ushort)KeyExchange.Length), 0, Data, 2, 2);
            Buffer.BlockCopy(KeyExchange, 0, Data, 4, KeyExchange.Length);
        }

        public static KeyShareEntry[] ExtractEntries(byte[] keyshareBytes)
        {
            var entries = new List<KeyShareEntry>();

            int index = 0;
            while (index < keyshareBytes.Length)
            {
                // read group
                var group = Utils.ToUInt16(keyshareBytes, index);
                index += 2;

                // read KeyExchange length
                int length = Utils.ToUInt16(keyshareBytes, index);
                index += 2;

                // read KeyExchange
                var keyExchange = new byte[length];
                Buffer.BlockCopy(keyshareBytes, index, keyExchange, 0, length);
                index += length;

                entries.Add(new KeyShareEntry((NamedGroup)group, keyExchange));
            }

            return entries.ToArray();
        }

    }
}
