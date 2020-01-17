using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Records
{
    public class ApplicationData : TLSRecord
    {
        public ApplicationData(byte[] payload) : base(RecordType.ApplicationData, ProtocolVersion.TLSv1_2, payload)
        {
        }
    }
}
