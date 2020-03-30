using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase.Protocol;
using SuperSocket.SocketBase.Command;
using TLSHandler.Enums;
using TLSHandler.Internal.TLS.Records;

namespace Https.Handler
{
    public class TLS_ChangeCipherSpec : CommandBase<TcpSession, Request.TLSRequest>
    {
        public override string Name => RecordType.ChangeCipherSpec.ToString();

        public override void ExecuteCommand(TcpSession session, Request.TLSRequest tlsRec)
        {
            var record = new ChangeCipherSpec(tlsRec.Payload);
            session.Receive(record);
           
        }
        
    }
}
