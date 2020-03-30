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
    public class TLS_Alert : CommandBase<TcpSession, Request.TLSRequest>
    {
        public override string Name => RecordType.Alert.ToString();

        public override void ExecuteCommand(TcpSession session, Request.TLSRequest tlsRec)
        {
            var record = new Alert(tlsRec.Payload);
            
            if(record.Level == AlertLevel.Fatal)
            {
                LogHelper.Error(session, $"Client sent Fatal Alert {record.Description.ToString()}");
                session.Close(SuperSocket.SocketBase.CloseReason.ClientClosing);
            }
        }
        
    }
}
