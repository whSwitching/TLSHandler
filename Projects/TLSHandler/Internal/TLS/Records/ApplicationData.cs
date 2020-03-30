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
        public byte[] IV { get { return Payload.Take(16).ToArray(); } }
        public byte[] EncryptedData { get { return Payload.Skip(16).ToArray(); } }

        public ApplicationData(byte[] payload) : base(RecordType.ApplicationData, ProtocolVersion.TLSv1_2, payload)
        {
        }

        public ApplicationData(byte[] header, byte[] payload) : base(header, payload)
        {
        }
    }
}
