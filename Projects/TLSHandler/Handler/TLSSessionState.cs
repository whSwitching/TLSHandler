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
        Client_Hello = 10,
        Server_Hello_Done = 20,        
        Client_Key_Exchange = 30,
        Client_ChangeCipherSpec = 40,
        Client_Certificate = 41,
        Client_CertificateVerify = 49,
        Client_Finished = 50,
        Server_ChangeCipherSpec = 60,
        Server_Finished = 100,
    }
}
