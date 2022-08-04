using System;

namespace bls_sharp
{
    public class BLSException : Exception
    {
        public BLSException(string message) : base(message)
        {
        }
    }
}