using System;
using System.Linq;
using System.Numerics;
using mcl;


namespace bls_sharp
{
    /// <summary>
    /// A class for interfacing BLS digital signature library.
    /// </summary>
    public class BLSInterface
    {
        // BLS library does have constant values for serialization, however, this has to be defined again due to 
        // constant value is not same as actual byte length.

        /// <summary>
        /// The byte length of private key.
        /// </summary>
        internal const int PrivateKeySize = 32;
        
        /// <summary>
        /// The byte length of public key.
        /// </summary>
        internal const int PublicKeySize = 48;
        
        /// <summary>
        /// The byte length of signature.
        /// </summary>
        internal const int SignatureSize = 96;

        /// <summary>
        /// The byte length of message.
        /// </summary>
        internal const int MessageSize = BLS.MSG_SIZE;

        /// <summary>
        /// Generates a new private key with CSPRNG.
        /// </summary>
        /// <returns>Returns a new private key in <see langword="byte"/> array.</returns>
        public static byte[] GeneratePrivateKey()
        {
            BLS.SecretKey secretKey;
            _ = BLS.blsSecretKeySetByCSPRNG(ref secretKey);
            return secretKey.Serialize();
        }

        /// <summary>
        /// Validates a private key.
        /// </summary>
        /// <param name="privateKey">a private key to verify.</param>
        /// <returns>Returns <see langword="true"/> if private is valid, otherwise returns <see langword="false"/>.
        /// </returns>
        public static bool ValidatePrivateKey(in byte[] privateKey)
        {
            ValidatePrivateKeyInput(privateKey);
            BLS.SecretKey secretKey;
            try
            {
                secretKey.Deserialize(privateKey);
                return true;
            }
            catch (ArithmeticException)
            {
                return false;
            }
        }

        /// <summary>
        /// Get a public key from private key.
        /// </summary>
        /// <param name="privateKey">A private key for get a public key.</param>
        /// <returns>Returns <see langword="byte"/> array public key of given private key.</returns>
        /// <exception cref="BLSInputException">Thrown if given private key is invalid.</exception>
        public static byte[] GetPublicKey(byte[] privateKey)
        {
            BLS.SecretKey secretKey;
            try
            {
                secretKey.Deserialize(privateKey);
                return secretKey.GetPublicKey().Serialize();
            }
            catch (ArithmeticException)
            {
                throw new BLSInputException("Private key is invalid.");
            }
        }

        /// <summary>
        /// Verifies a signature with given public key and message.
        /// </summary>
        /// <param name="publicKey">A public key of given signature.</param>
        /// <param name="signature">A signature of given message.</param>
        /// <param name="message">A message created by signature.</param>
        /// <exception cref="BLSInputException">Thrown if given input length is not <see cref="SignatureSize"/>,
        /// <see cref="PublicKeySize"/>, <see cref="MessageSize"/>.
        /// </exception>
        /// <returns>Returns <see langword="true"/> if signature is valid with given public key and signature, otherwise
        /// returns <see langword="false"/>.
        /// </returns>
        public static bool Verify(byte[] publicKey, byte[] signature, byte[] message)
        {
            ValidatePublicKeyInput(publicKey);
            ValidateSignatureInput(signature);

            BLS.Signature sig;
            BLS.PublicKey pk;
            try
            {
                pk.Deserialize(publicKey);
                sig.Deserialize(signature);
                return pk.Verify(sig, message);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Signs a message with private key in this <see cref="BLSInterface"/>.
        /// </summary>
        /// <param name="privateKey">A private key used to sign.</param>
        /// <param name="message">A message to sign.</param>
        /// <returns>Returns serialized signature in byte array.</returns>
        public static byte[] Sign(byte[] privateKey, byte[] message)
        {
            ValidateMessageInput(message);
            ValidatePrivateKeyInput(privateKey);

            BLS.SecretKey secretKey;
            try
            {
                secretKey.Deserialize(privateKey);
            }
            catch (ArithmeticException)
            {
                throw new BLSInputException("Private key is invalid.");
            }

            BLS.Signature sig = secretKey.Sign(message);
            return sig.Serialize();
        }

        /// <summary>
        /// Verifies a message with given aggregated signature and used public keys.
        /// </summary>
        /// <param name="signature">A aggregated signature.</param>
        /// <param name="publicKeys">The public keys used to sign.</param>
        /// <param name="message">A message to verify.</param>
        /// <returns></returns>
        public static bool FastAggregateVerify(byte[] signature, byte[][] publicKeys, byte[] message)
        {
            switch (publicKeys.Length)
            {
                case 1:
                    return Verify(publicKeys[0], signature, message);
                case 0:
                    throw new BLSInputException("Public keys cannot be empty");
            }

            var sig = new BLS.Signature();
            ValidateSignatureInput(signature);
            try
            {
                sig.Deserialize(signature);
            }
            catch (ArithmeticException)
            {
                return false;
            }

            var pks = new BLS.PublicKey[publicKeys.Length];
            for (var i = 0; i < publicKeys.Length; i++)
            {
                ValidatePublicKeyInput(publicKeys[i]);
                pks[i].Deserialize(publicKeys[i]);
            }

            return BLS.FastAggregateVerify(sig, pks, message);
        }

        /// <summary>
        /// Verifies a message with given aggregated signature and used public keys.
        /// </summary>
        /// <param name="signature">A aggregated signature.</param>
        /// <param name="publicKeys">The public keys used to sign.</param>
        /// <param name="messages">A 32-bytes long messages.</param>
        /// <returns></returns>
        public static bool AggregateVerify(byte[] signature, byte[][] publicKeys, byte[][] messages)
        {
            var sig = new BLS.Signature();
            if (publicKeys.Length != messages.Length)
            {
                throw new BLSInputException("Public keys and messages must have same rank.");
            }

            if (publicKeys.Length == 0)
            {
                throw new BLSInputException("Public keys cannot be empty");
            }

            if (messages.Length == 0)
            {
                throw new BLSInputException("Messages cannot be empty");
            }

            ValidateSignatureInput(signature);
            try
            {
                sig.Deserialize(signature);
            }
            catch (ArithmeticException)
            {
                return false;
            }

            var pks = new BLS.PublicKey[publicKeys.Length];
            for (var i = 0; i < publicKeys.Length; i++)
            {
                ValidatePublicKeyInput(publicKeys[i]);
                pks[i].Deserialize(publicKeys[i]);
            }

            BLS.Msg[] msg = new BLS.Msg[messages.Length];
            for (var i = 0; i < messages.Length; i++)
            {
                ValidateMessageInput(messages[i]);
                msg[i].Set(messages[i]);
            }

            return BLS.AggregateVerify(sig, pks, msg);
        }

        /// <summary>
        /// Verifies multiple messages. Each given public key, signature, and message should be placed in same order,
        /// index.
        /// </summary>
        /// <param name="signatures">A signature to verify.</param>
        /// <param name="publicKeys">A public key used to verify.</param>
        /// <param name="messages">A message used to sign.</param>
        /// <returns>Returns <see langword="true"/> if given batch signatures are <see langword="true"/>,
        /// <see langword="false"/> if any signatures is invalid.</returns>
        /// <exception cref="BLSInputException">Thrown if given inputs length is not same or any invalid value is given.
        /// </exception>
        public static bool MultiVerify(byte[][] signatures, byte[][] publicKeys, byte[][] messages)
        {
            if (signatures.Length != publicKeys.Length && signatures.Length != messages.Length)
            {
                throw new BLSInputException("Signatures, Public Keys and Messages length are not matching.");
            }

            if (publicKeys.Length == 0)
            {
                throw new BLSInputException("Public key must not be empty.");
            }

            if (signatures.Length == 0)
            {
                throw new BLSInputException("Signature must not be empty");
            }

            if (messages.Length == 0)
            {
                throw new BLSInputException("Message must not be empty.");
            }

            var n = signatures.Length;

            var sigs = new BLS.Signature[n];
            var pks = new BLS.PublicKey[n];
            var msgs = new BLS.Msg[n];
            var rands = new BLS.SecretKey[n];

            for (var i = 0; i < signatures.Length; ++i)
            {
                try
                {
                    sigs[i].Deserialize(signatures[i]);
                    pks[i].Deserialize(publicKeys[i]);
                    msgs[i].Set(messages[i]);
                    _ = BLS.blsSecretKeySetByCSPRNG(ref rands[i]);
                }
                catch (ArithmeticException)
                {
                    throw new BLSInputException("Some of inputs are invalid.");
                }
            }

            return BLS.MultiVerify(sigs, pks, msgs, rands);
        }

        /// <summary>
        /// Aggregates the given signatures and returns aggregated signature.
        /// </summary>
        /// <param name="lhs">an one signature to aggregate.</param>
        /// <param name="rhs">an other signature to aggregate.</param>
        /// <returns>Returns a aggregated signature with two signatures.</returns>
        /// <exception cref="BLSInputException">Thrown when given signatures are invalid.</exception>
        public static byte[] AggregateSignatures(byte[] lhs, byte[] rhs)
        {
            if (lhs.SequenceEqual(rhs))
            {
                return rhs;
            }

            BLS.Signature rhsSig;
            try
            {
                rhsSig.Deserialize(rhs);
            }
            catch (ArithmeticException)
            {
                throw new BLSInputException("Right hand-side signature is invalid");
            }

            BLS.Signature lhsSig;
            try
            {
                lhsSig.Deserialize(lhs);
            }
            catch (ArithmeticException)
            {
                throw new BLSInputException("Left hand-side signature is invalid");
            }

            lhsSig.Add(rhsSig);

            return lhsSig.Serialize();
        }

        private static void ValidateSignatureInput(in byte[] signature)
        {
            if (signature.Length != SignatureSize)
            {
                throw new BLSInputException(
                    $"Given signature is not of the correct size. " +
                    $"(expected: {SignatureSize}, actual: {signature.Length})");
            }
        }

        private static void ValidatePrivateKeyInput(in byte[] privateKey)
        {
            BigInteger val = new BigInteger(privateKey);
            if (val.Equals(BigInteger.Zero))
            {
                throw new BLSPrivateKeyException("Private key cannot be zero.");
            }

            if (privateKey.Length != PrivateKeySize)
            {
                throw new BLSPrivateKeyException("Given private Key is not of the correct size.");
            }
        }

        private static void ValidatePublicKeyInput(in byte[] publicKey)
        {
            if (publicKey.Length != PublicKeySize)
            {
                throw new BLSInputException("Given public Key is not of the correct size.");
            }
        }
        
        private static void ValidateMessageInput(in byte[] message)
        {
            if (message.Length != MessageSize)
            {
                throw new BLSInputException(
                    $"Given message is not of the correct size." +
                    $"(expected: {MessageSize}, actual: {message.Length})");
            }
        }
    }
}