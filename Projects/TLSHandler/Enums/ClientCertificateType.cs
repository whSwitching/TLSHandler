using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.4
    public enum ClientCertificateType : byte
    {
        rsa_sign = 1,
        dss_sign = 2,
        rsa_fixed_dh = 3,
        dss_fixed_dh = 4,
        rsa_ephemeral_dh_RESERVED = 5,
        dss_ephemeral_dh_RESERVED = 6,
        fortezza_dms_RESERVED = 20,
    }
}
