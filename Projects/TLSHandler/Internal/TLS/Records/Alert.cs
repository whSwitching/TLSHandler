using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Records
{
    public class Alert : TLSRecord
    {
        public AlertLevel Level { get { return (AlertLevel)Payload[0]; } }
        public AlertDescription Description { get { return (AlertDescription)Payload[1]; } }

        public Alert(byte[] payload) : base(RecordType.Alert, ProtocolVersion.TLSv1_2, payload)
        {
        }

        public Alert(AlertLevel level, AlertDescription desc) : base(RecordType.Alert, ProtocolVersion.TLSv1_2, new[] { (byte)level, (byte)desc })
        {
        }

        public static Alert Fatal(AlertDescription desc)
        {
            return new Alert(AlertLevel.Fatal, desc);
        }
    }
}
