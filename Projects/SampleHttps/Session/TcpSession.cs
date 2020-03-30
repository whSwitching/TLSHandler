using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase;
using TLSHandler.Enums;
using TLSHandler.Handler;
using TLSHandler.Internal.TLS.Records;

namespace Https
{
    public class TcpSession : AppSession<TcpSession, Request.TLSRequest>
    {
        public Context TLSContext { get; internal set; }

        object _lock = new object();

        public void Receive(TLSRecord record)
        {
            lock(_lock)
            {
                var response = this.TLSContext.Process_Record(record);
                this.Send(response);
            }
            
        }

        public void Send(Result resp)
        {
            if (resp != null)
            {
                if (resp is PacketResult hr)
                {
                    this.Send(hr.Response);
                }
                else if (resp is AlertResult ar)
                {
                    LogHelper.Error(this, ar);
                    if (ar.ShouldTerminate)
                        this.Close(CloseReason.ApplicationError);
                    return;
                }
            }
        }

        public void Send(IEnumerable<TLSRecord> tls)
        {
            var recordsBytes = new List<byte>();
            foreach (var pkt in tls)
            {
                LogHelper.Debug(this, $"SEND TLS {pkt.Type}");
                recordsBytes.AddRange(pkt.Data);
            }

            Send(recordsBytes.ToArray(), 0, recordsBytes.Count);
            
        }

        public void SendApplicationData(byte[] data)
        {
            var resp = this.TLSContext.GetEncryptedPacket(data);
            if (resp != null)
            {
                if (resp is PacketResult hr)
                {
                    this.Send(hr.Response);
                }
                else if (resp is AlertResult ar)
                {
                    LogHelper.Error(this, ar);
                    if (ar.ShouldTerminate)
                        this.Close(CloseReason.ApplicationError);
                    return;
                }
            }
        }
    }
}
