using System;

namespace bls_sharp
{
    public class BLSPublicKeyException : BLSException
    {
        public BLSPublicKeyException(string message) : base(message)
        {
        }
    }
}