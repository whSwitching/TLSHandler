using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.1.3
    //https://tools.ietf.org/html/rfc8446#section-4.1.3
    class ServerHello : FragmentBody
    {
        public ProtocolVersion ProtocolVersion { get; private set; }

        public ValueTypes.Random Random { get; private set; }

        public ValueTypes.Session Session { get; private set; }

        public CipherSuite CipherSuite { get; private set; }

        public CompressionMethod CompressionMethod { get; private set; }

        public Extensions.Extension[] Extensions { get; private set; }

        public ushort ExtensionsLength { get; private set; }

        public ServerHello(ProtocolVersion protocolVersion, ValueTypes.Random random, ValueTypes.Session session, CipherSuite cipher, Extensions.Extension[] extensions = null) : base(null)
        {
            this.ProtocolVersion = protocolVersion;
            this.Random = random;
            this.Session = session;
            this.CipherSuite = cipher;
            this.CompressionMethod = CompressionMethod.NO_COMPRESSION;
            this.Extensions = extensions;
            this.ExtensionsLength = TLS.Extensions.Extension.GetLength(extensions);

            byte[] bytes_random = this.Random.Data;
            byte[] bytes_session = this.Session.Data;

            // length of the Handshake Header payload (aka the ServerHello message)
            int length = 2;                     // 2 bytes ProtocolVersion
            length += bytes_random.Length;      //   bytes ServerRandom
            length += bytes_session.Length;     // 1 byte SessionIDLength + bytes SessionID
            length += 2;                        // 2 bytes CipherSuite
            length += 1;                        // 1 byte CompressionMethod
            length += 2;                        // 2 bytes ExtensionsLength
            length += this.ExtensionsLength;    // total bytes of extensions

            Data = new byte[length];
            int index = 0;
            // ProtocolVersion
            Data[index] = (byte)(((ushort)ProtocolVersion & 0xff00) >> 8);
            Data[index + 1] = (byte)((ushort)ProtocolVersion & 0x00ff);
            index += 2;
            // ServerRandom
            Buffer.BlockCopy(bytes_random, 0, Data, index, bytes_random.Length);
            index += bytes_random.Length;
            // SessionIDLength + SessionID
            Buffer.BlockCopy(bytes_session, 0, Data, index, bytes_session.Length);
            index += bytes_session.Length;
            // CipherSuite
            Data[index] = (byte)(((ushort)this.CipherSuite & 0xff00) >> 8);
            Data[index + 1] = (byte)((ushort)this.CipherSuite & 0x00ff);
            index += 2;
            // CompressionMethod
            Data[index] = (byte)this.CompressionMethod;
            index += 1;
            // ExtensionsLength
            Data[index] = (byte)((this.ExtensionsLength & 0xff00) >> 8);
            Data[index + 1] = (byte)(this.ExtensionsLength & 0x00ff);
            index += 2;
            // Extensions
            if (this.Extensions != null)
            {
                foreach (var e in this.Extensions)
                {
                    var extBytes = e.Data;
                    Buffer.BlockCopy(extBytes, 0, Data, index, extBytes.Length);
                    index += extBytes.Length;
                }
            }
        }

    }
}
