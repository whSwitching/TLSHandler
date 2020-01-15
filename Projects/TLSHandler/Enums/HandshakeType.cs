using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc5246#section-7.4
    //https://tools.ietf.org/html/rfc8446#section-4
    public enum HandshakeType : byte
    {
        Hello_Request = 0x00,
        Client_Hello = 0x01,
        Server_Hello = 0x02,
        New_Session_Ticket = 0x04,
        End_Of_EarlyData = 0x05,
        Encrypted_Extensions = 0x08,
        Certificate = 0x0B,
        Server_Key_Exchange = 0x0C,
        Certificate_Request = 0x0D,
        Server_Hello_Done = 0x0E,
        Certificate_Verify = 0x0F,
        Client_Key_Exchange = 0x10,
        Finished = 0x14,
        Key_Update = 0x18,
        Message_Hash = 0xFE,
        Undefined = 0xFF
    }
}
