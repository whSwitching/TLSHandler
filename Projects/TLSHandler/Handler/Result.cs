using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLS = TLSHandler.Internal.TLS;

namespace TLSHandler.Handler
{
    public abstract class Result
    {
        public static AlertResult FatalAlert(Enums.AlertDescription desc, string message)
        {
            return new AlertResult(desc, message);
        }
    }

    /// <summary>
    /// decrypted/encrypted application data
    /// </summary>
    public class ApplicationResult : Result
    {
        public byte[] Data { get; set; }

        public ApplicationResult(byte[] appData)
        {
            Data = appData;
        }
    }

    /// <summary>
    /// something may not right, alert message
    /// </summary>
    public class AlertResult : Result
    {
        public Enums.AlertDescription Description { get; set; }
        public bool ShouldTerminate { get; set; }
        public string DebugMessage { get; set; }

        public AlertResult(Enums.AlertDescription desc, string message, bool terminate = true)
        {
            Description = desc;
            DebugMessage = message;
            ShouldTerminate = terminate;
        }

        public override string ToString()
        {
            return $"{Description} ({ShouldTerminate}): {DebugMessage}";
        }
    }

    /// <summary>
    /// packets result has to be sent out
    /// </summary>
    public class PacketResult : Result
    {
        public TLS.Records.TLSRecord[] Response { get; set; }

        public PacketResult(TLS.Records.TLSRecord[] resps)
        {
            Response = resps;
        }
    }
}
