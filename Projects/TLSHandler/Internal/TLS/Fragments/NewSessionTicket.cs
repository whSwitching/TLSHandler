using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc8446#section-4.6.1
    public class NewSessionTicket : FragmentBody
    {
        public uint LifetimeSecs { get; private set; }
        public uint AgeAdd { get; private set; }
        public byte[] Nonce { get; private set; }
        public byte[] Ticket { get; private set; }
        public Extensions.Extension[] Extensions { get; private set; }


        public NewSessionTicket(uint lifetime, uint ageadd, byte[] nonce, byte[] ticket, Extensions.Extension[] extension = null) : base(null)
        {
            LifetimeSecs = lifetime;
            AgeAdd = ageadd;
            Nonce = nonce;
            Ticket = ticket;
            Extensions = extension;

            using (var ms = new System.IO.MemoryStream())
            {
                ms.WriteValue(LifetimeSecs);
                ms.WriteValue(AgeAdd);
                ms.WriteValue(Nonce, new byte[] { (byte)Nonce.Length });            // 1 byte length + Nonce
                ms.WriteValue(Ticket, Utils.UInt16Bytes((ushort)Ticket.Length));    // 2 byte length + Ticket
                if (Extensions == null)
                    ms.Write(new byte[] { 0x00, 0x00 }, 0, 2);
                else
                {
                    var extBytes = new List<byte>();
                    foreach (var ext in Extensions)
                        extBytes.AddRange(ext.Data);
                    ms.WriteValue(extBytes.ToArray(), Utils.UInt16Bytes((ushort)extBytes.Count));
                }

                Data = ms.ToArray();
            }
        }

        public static NewSessionTicket Random(byte nonce)
        {
            var rd = new Random(DateTime.Now.Millisecond);
            var ticket = new byte[100];
            rd.NextBytes(ticket);
            return new NewSessionTicket(3600, 1000, new byte[] { nonce }, ticket);
        }
    }
}
