using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.Facility.Protocol;
using SuperSocket.SocketBase.Protocol;

namespace Https.Filter
{
    class TLSPacketFilter : FixedHeaderReceiveFilter<Request.TLSRequest>
    {
        // 5 bytes header for tls record
        public TLSPacketFilter() : base(5) 
        {
        }

        protected override int GetBodyLengthFromHeader(byte[] header, int offset, int length)
        {
            return GetBodyLength_TLS(header, offset, length);
        }

        protected override Request.TLSRequest ResolveRequestInfo(ArraySegment<byte> header, byte[] bodyBuffer, int offset, int length)
        {
            var body = bodyBuffer.Skip(offset).Take(length).ToArray();
            var ret = new Request.TLSRequest(header.ToArray(), body);
            LogHelper.Debug(this, $"RECEIVE TLS {ret.Type}");
            return ret;
        }

        private int GetBodyLength_TLS(byte[] header, int offset, int length)
        {
            var hd = header.Skip(offset).Take(length).ToArray();            
            var len = ((hd[3] << 8) + hd[4]);

            return len;
        }

    }
}
