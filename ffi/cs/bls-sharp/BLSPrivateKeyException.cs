using System;

namespace bls_sharp
{
    public class BLSPrivateKeyException : BLSException
    {
        public BLSPrivateKeyException(string message) : base(message)
        {
        }
    }
}