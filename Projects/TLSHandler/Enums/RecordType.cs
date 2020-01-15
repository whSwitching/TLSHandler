using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    public enum RecordType : byte
    {
        Invalid = 0x00,
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        ApplicationData = 0x17,
        Heartbeat = 0x18
    }
}
