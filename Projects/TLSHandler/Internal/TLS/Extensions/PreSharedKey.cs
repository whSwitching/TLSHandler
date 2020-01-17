using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.11
    class PreSharedKey : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.PRE_SHARED_KEY; } }

        public ClientOfferedPsks ClientOffered { get; private set; }    // when client_hello
        public ushort? ServerSelectedIdentity { get; private set; }     // when server_hello

        public PreSharedKey(byte[] clientExtensionBytes) : base(clientExtensionBytes)
        {
            ClientOffered = new ClientOfferedPsks(clientExtensionBytes.Skip(4).ToArray());
        }

        public PreSharedKey(ushort selectedIdentity) : base(null)
        {
            ServerSelectedIdentity = selectedIdentity;

            Data = new byte[6];
            Buffer.BlockCopy(Utils.UInt16Bytes((ushort)Type), 0, Data, 0, 2);
            Buffer.BlockCopy(new byte[] { 0x00, 0x02 }, 0, Data, 2, 2);
            Buffer.BlockCopy(Utils.UInt16Bytes(selectedIdentity), 0, Data, 4, 2);
        }
    }

    public class ClientOfferedPsks : PacketData
    {
        public ushort IdentitiesLength { get { return Utils.ToUInt16(Data, 0); } }
        public PskIdentity[] Identities { get; private set; }
        public PskBinders Binders { get; private set; }

        public ClientOfferedPsks(byte[] body)
        {
            Data = body;
            Identities = PskIdentity.Extract(body.Skip(2).Take(IdentitiesLength).ToArray());
            Binders = new PskBinders(body.Skip(2 + IdentitiesLength).ToArray());
        }
    }

    public class PskIdentity : PacketData
    {
        public ushort IdentityLength { get { return Utils.ToUInt16(Data, 0); } }
        public byte[] Identity { get { return Data.Skip(2).Take(IdentityLength).ToArray(); } }
        public uint ObfuscatedTicketAge { get { return Utils.ToUInt32(Data, Data.Length - 4); } }

        public static PskIdentity[] Extract(byte[] identitiesBytes)
        {
            var ret = new List<PskIdentity>();
            var idx = 0;
            while (idx < identitiesBytes.Length)
            {
                var identityLen = Utils.ToUInt16(identitiesBytes, idx);
                var bodyBytes = identitiesBytes.Skip(idx).Take(2 + identityLen + 4).ToArray();
                ret.Add(new PskIdentity(bodyBytes));
                idx += bodyBytes.Length;
            }
            return ret.ToArray();
        }

        PskIdentity(byte[] body)
        {
            Data = body;
        }
    }

    public class PskBinders : PacketData
    {
        public ushort BindersLength { get { return Utils.ToUInt16(Data, 0); } }
        public byte[] Binders { get { return Data.Skip(2).Take(BindersLength).ToArray(); } }

        public PskBinders(byte[] body)
        {
            Data = body;
        }
    }
}
