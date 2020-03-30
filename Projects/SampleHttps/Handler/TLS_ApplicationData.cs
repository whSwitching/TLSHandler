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
    public class TLS_ApplicationData : CommandBase<TcpSession, Request.TLSRequest>
    {
        public override string Name => RecordType.ApplicationData.ToString();

        public override void ExecuteCommand(TcpSession session, Request.TLSRequest tlsRec)
        {
            var record = new ApplicationData(tlsRec.Header, tlsRec.Payload);

            var tlsPayload = ReceiveApplicationData(session, record);
            if (tlsPayload != null)
            {
                var request = Encoding.ASCII.GetString(tlsPayload).Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                var response = HTTP_Handler.GetResponseData(session, request);

                session.SendApplicationData(response);
            }
        }

        byte[] ReceiveApplicationData(TcpSession session, ApplicationData tls)
        {
            var resp = session.TLSContext.Process_Record(tls);
            if (resp != null)
            {
                if (resp is PacketResult hr)
                {
                    session.Send(hr.Response);
                }
                else if (resp is AlertResult ar)
                {
                    LogHelper.Error(this, ar);
                    if (ar.ShouldTerminate)
                        session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                }
                else if (resp is ApplicationResult app)
                {
                    return app.Data;
                }
                return null;
            }
            else
            {
                if (session.TLSContext.State != TLSSessionState.Client_Finished)
                {
                    LogHelper.Error(session, $"unknown error when decrypt ApplicationData");
                    session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                }
                return null;
            }
        }
        
    }
}
