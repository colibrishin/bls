using System;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text;
using mcl;
using Xunit;
using Xunit.Abstractions;

namespace bls_sharp.Tests
{
    public class Sign
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Sign(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void SimpleSign()
        {
            var privateKey = BLSInterface.GeneratePrivateKey();
            var publicKey = BLSInterface.GetPublicKey(privateKey);
            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);

            var sign = BLSInterface.Sign(privateKey, hashedMessage);
            Assert.NotNull(sign);
            var verify = BLSInterface.Verify(publicKey, sign, hashedMessage);
            Assert.True(verify);
        }
        
        [Fact]
        public void SimpleSignSerialize()
        {
            var privateKey = BLSInterface.GeneratePrivateKey();
            var message = new byte[] { 0xff, 0xff, 0xff, 0xff };
            var hashedMessage = SHA256.Create().ComputeHash(message);
            var sign = BLSInterface.Sign(privateKey, hashedMessage);

            BLS.Signature sig;
            
            sig.Deserialize(sign);
            var unmarshal = sig.Serialize();
            Assert.Equal(sign, unmarshal);
        }

        [Fact]
        public void DeserializeTest()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G2/");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestBase.ParseTest(sReader);

                var signature = HexUtil.ToBytes(testYaml.Input["signature"]);
                var expectedResult = bool.Parse(testYaml.Output);
                bool result;

                BLS.Signature sig;
                try
                {
                    sig.Deserialize(signature);
                    result = true;
                }
                catch (ArithmeticException)
                {
                    result = false;
                }

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }

        [Fact]
        public void AggregateSignTest()
        {
            var files = Directory.GetFiles("../../../../tests/aggregate/");

            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestSingleBase.ParseTest(sReader);

                var signatures = testYaml.Input.Select(HexUtil.ToBytes).ToArray();

                var aggSignature = signatures.FirstOrDefault();
                aggSignature ??= new byte[BLSInterface.SignatureSize];

                var expectedSignature = new byte[BLSInterface.SignatureSize];

                if (!(testYaml.Output is null))
                {
                    expectedSignature = HexUtil.ToBytes(testYaml.Output); 
                }
                var nextSignatures = signatures.Skip(1).ToArray();

                if (signatures.Length == 1)
                {
                    aggSignature = BLSInterface.AggregateSignatures(aggSignature, aggSignature);
                }
                else
                {
                    foreach (var nextSign in nextSignatures)
                    {
                        aggSignature = BLSInterface.AggregateSignatures(aggSignature, nextSign);
                    }
                }

                _testOutputHelper.WriteLine("Aggregated Signature: \n" + BitConverter.ToString(aggSignature));
                _testOutputHelper.WriteLine("Expected Signature: \n" + BitConverter.ToString(expectedSignature));
                _testOutputHelper.WriteLine("=====");
                Assert.Equal(expectedSignature, aggSignature);
            }

        }
        
        [Fact]
        public void SignTest()
        {
            var files = Directory.GetFiles("../../../../tests/sign/");

            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestBase.ParseTest(sReader);

                var privateKey = HexUtil.ToBytes(testYaml.Input["privkey"]);
                var message = HexUtil.ToBytes(testYaml.Input["message"]);

                if (privateKey.SequenceEqual(new byte[privateKey.Length]))
                {
                    Assert.Throws<BLSPrivateKeyException>(
                        () => BLSInterface.Sign(privateKey, message));
                }
                else
                {
                    var expectedSign = HexUtil.ToBytes(testYaml.Output);
                    
                    var sign = BLSInterface.Sign(privateKey, message);

                    _testOutputHelper.WriteLine("Private key: \n" + BitConverter.ToString(privateKey));
                    _testOutputHelper.WriteLine("Message in String: \n" + Encoding.ASCII.GetString(message));
                    _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                    _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(sign));
                    _testOutputHelper.WriteLine("Expected Signature: \n" + BitConverter.ToString(expectedSign));
                    _testOutputHelper.WriteLine("======");
                    Assert.Equal(expectedSign, sign);
                }
            }

        }
    }
}