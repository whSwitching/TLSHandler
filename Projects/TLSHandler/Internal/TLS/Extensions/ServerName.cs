using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc6066#section-3
    class ServerName : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.SERVER_NAME; } }

        public ushort EntriesLength { get { return Utils.ToUInt16(Data, 4); } }

        public ServerNameEntry[] Entries { get; private set; }

        public ServerName(byte[] extensionBytes) : base(extensionBytes)
        {
            var entriesBytes = Data.Skip(6).ToArray();
            Entries = ServerNameEntry.ExtractEntries(entriesBytes);
        }
    }

    class ServerNameEntry : PacketData
    {
        public ServerNameType NameType { get; private set; }
        public string Name { get; private set; }

        public ServerNameEntry(ServerNameType type, string name)
        {
            NameType = type;
            Name = name;

            Data = new byte[1 + 2 + Name.Length];
            Data[0] = (byte)NameType;

            var bytesName = Encoding.ASCII.GetBytes(Name);
            var bytesLen = Utils.UInt16Bytes((ushort)bytesName.Length);

            Buffer.BlockCopy(bytesLen, 0, Data, 1, 2);
            Buffer.BlockCopy(bytesName, 0, Data, 3, bytesName.Length);
        }

        public static ServerNameEntry[] ExtractEntries(byte[] namelistBytes)
        {
            var entries = new List<ServerNameEntry>();

            int index = 0;

            while (index < namelistBytes.Length)
            {
                // read type
                var type = namelistBytes[index];
                index += 1;

                // read name length
                int length = (ushort)((namelistBytes[index] << 8) | namelistBytes[index + 1]);
                index += 2;

                // read name
                var name = new byte[length];
                Buffer.BlockCopy(namelistBytes, index, name, 0, length);
                index += length;

                entries.Add(new ServerNameEntry((ServerNameType)type, Encoding.ASCII.GetString(name)));
            }

            return entries.ToArray();
        }

    }
}
