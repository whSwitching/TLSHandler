using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Handler
{
    public enum TLSSessionState : byte
    {
        None = 0,
        Client_Hello = 3,
        Server_Hello_Done = 4,
        Client_Key_Exchange = 5,
        Client_ChangeCipherSpec = 6,
        Client_Finished = 7,
        Server_ChangeCipherSpec = 8,
        Server_Finished = 10,
    }
}
