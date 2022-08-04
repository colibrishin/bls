using System;
using System.IO;
using System.Linq;
using mcl;
using Xunit;
using Xunit.Abstractions;

namespace bls_sharp.Tests
{
    public class PublicKey
    {
        private ITestOutputHelper _testOutputHelper;
        
        public PublicKey(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }        
        [Fact]
        public void Serialize()
        {
            var privateKey = BLSInterface.GeneratePrivateKey();
            var publicKey = BLSInterface.GetPublicKey(privateKey);
            Assert.NotNull(publicKey);
            Assert.Equal(BLSInterface.PublicKeySize, publicKey.Length);
        }

        [Fact]
        public void Deserialize()
        {
            var files = Directory.GetFiles("../../../../tests/deserialization_G1/");

            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestBase.ParseTest(sReader);

                var publicKey = HexUtil.ToBytes(testYaml.Input["pubkey"]);
                var expectedResult = bool.Parse(testYaml.Output);
                bool result;

                BLS.PublicKey pk;
                try
                {
                    pk.Deserialize(publicKey);
                    result = true;
                }
                catch (ArithmeticException)
                {
                    result = false;
                }

                _testOutputHelper.WriteLine("Public key: \n" + BitConverter.ToString(publicKey));
                _testOutputHelper.WriteLine("Expected results: \n" + expectedResult);
                _testOutputHelper.WriteLine("======");
                Assert.Equal(expectedResult, result);
            }
        }
    }
}