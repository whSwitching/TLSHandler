using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Records
{
    public class ChangeCipherSpec : TLSRecord
    {
        public ChangeCipherSpec(byte[] payload) : base(RecordType.ChangeCipherSpec, ProtocolVersion.TLSv1_2, payload)
        {
        }

        public ChangeCipherSpec() : base(RecordType.ChangeCipherSpec, ProtocolVersion.TLSv1_2, new byte[] { 0x01 })
        {
        }
    }
}
