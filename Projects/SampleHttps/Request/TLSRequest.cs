using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase.Protocol;

namespace Https.Request
{
    public class TLSRequest : TLSHandler.Internal.TLS.Records.TLSRecord, IRequestInfo<byte[]>
    {
        public string Key { get; protected set; }

        public byte[] Header = null;
        public byte[] Body => this.Payload;

        public TLSRequest(byte[] header, byte[] payload) : base(header, payload)
        {
            this.Key = Type.ToString();
            this.Header = header;
        }

    }
}
