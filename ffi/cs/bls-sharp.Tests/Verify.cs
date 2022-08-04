using System;
using System.IO;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace bls_sharp.Tests
{
    public class Verify
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Verify(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }
        
        [Fact]
        public void MultiVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/batch_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);
            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;

                var testYaml = BLSTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(HexUtil.ToBytes).ToArray();
                var messages = testYaml.Input["messages"].Select(HexUtil.ToBytes).ToArray();
                var signatures = testYaml.Input["signatures"].Select(HexUtil.ToBytes).ToArray();
                var expectedResult = bool.Parse(testYaml.Output);

                result = BLSInterface.MultiVerify(signatures, publicKeys, messages);

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg));   
                }
                _testOutputHelper.WriteLine("Signatures: ");
                foreach (var sig in signatures)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(sig));   
                }
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }
        
        [Fact]
        public void AggregateVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/aggregate_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);
            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;
                
                var testYaml = BLSTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(HexUtil.ToBytes).ToArray();
                var messages = testYaml.Input["messages"].Select(HexUtil.ToBytes).ToArray();
                var signature = HexUtil.ToBytes(testYaml.Input["signature"].First());
                var expectedResult = bool.Parse(testYaml.Output);

                if (publicKeys.Length == 0)
                {
                    Assert.Throws<BLSInputException>(
                        () => BLSInterface.AggregateVerify(signature, publicKeys, messages));
                    result = false;
                }
                else if (signature.Length != BLSInterface.SignatureSize)
                {
                    Assert.Throws<BLSInputException>(
                        () => BLSInterface.AggregateVerify(signature, publicKeys, messages));
                    result = false;
                }
                else
                {
                    result = BLSInterface.AggregateVerify(signature, publicKeys, messages);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Messages: ");
                foreach (var msg in messages)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(msg));   
                }
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }
        
        [Fact]
        public void FastAggregateVerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/fast_aggregate_verify/");
            _testOutputHelper.WriteLine("IsLittleEndian : " + BitConverter.IsLittleEndian);
            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                bool result;
                
                var testYaml = BLSTestListBase.ParseTest(sReader);

                var publicKeys = testYaml.Input["pubkeys"].Select(HexUtil.ToBytes).ToArray();
                var message = HexUtil.ToBytes(testYaml.Input["message"].First());
                var signature = HexUtil.ToBytes(testYaml.Input["signature"].First());
                var expectedResult = bool.Parse(testYaml.Output);

                if (publicKeys.Length == 0)
                {
                    Assert.Throws<BLSInputException>(
                        () => BLSInterface.FastAggregateVerify(signature, publicKeys, message));
                    result = false;
                }
                else
                {
                    result = BLSInterface.FastAggregateVerify(signature, publicKeys, message);
                }

                _testOutputHelper.WriteLine("Public key: ");
                foreach (var pk in publicKeys)
                {
                    _testOutputHelper.WriteLine(BitConverter.ToString(pk));
                }
                _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }

        [Fact]
        public void VerifyTest()
        {
            var files = Directory.GetFiles("../../../../tests/verify/");

            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestBase.ParseTest(sReader);

                var publicKey = HexUtil.ToBytes(testYaml.Input["pubkey"]);
                var message = HexUtil.ToBytes(testYaml.Input["message"]);
                var signature = HexUtil.ToBytes(testYaml.Input["signature"]);
                var expectedResult = bool.Parse(testYaml.Output);

                var result = BLSInterface.Verify(publicKey, signature, message);

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Message: \n" + BitConverter.ToString(message));
                _testOutputHelper.WriteLine("Signature: \n" + BitConverter.ToString(signature));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }
    }
}