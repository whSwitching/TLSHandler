using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase.Protocol;
using SuperSocket.SocketBase.Command;
using TLSHandler.Enums;
using TLSHandler.Handler;
using TLSHandler.Internal.TLS.Records;

namespace Https.Handler
{
    public class TLS_Handshake : CommandBase<TcpSession, Request.TLSRequest>
    {
        public override string Name => RecordType.Handshake.ToString();

        public override void ExecuteCommand(TcpSession session, Request.TLSRequest tlsRec)
        {
            var record = new Handshake(tlsRec.Payload);

            if (session.TLSContext == null)
            {
                session.TLSContext = new Context(((HttpServer)session.AppServer).PublicKeyFile, ((HttpServer)session.AppServer).PrivateKeyFile);
                var response = session.TLSContext.Initialize(record);
                session.Send(response);
            }
            else
            {
                session.Receive(record);
            }
        }
        
    }
}
