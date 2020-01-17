using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    interface ISignature
    {
        Enums.SignatureAlgorithm Algorithm { get; }

        byte[] Hash(byte[] data);

        byte[] Sign(byte[] data, object privateParameters);

    }
}
