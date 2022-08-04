using System;
using System.IO;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace bls_sharp.Tests
{
    public class PrivateKey
    {
        private ITestOutputHelper _testOutputHelper;

        public PrivateKey(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }
        
        [Fact]
        public void ZeroPrivateKey()
        {
            var privateKey = new byte[BLSInterface.PrivateKeySize];
            
            Assert.Throws<BLSPrivateKeyException>(
                () => BLSInterface.ValidatePrivateKey(privateKey));
        }
        
        [Fact]
        public void InvalidLengthPrivateKey()
        {
            var privateKey = new byte[BLSInterface.PrivateKeySize - 1];
            privateKey[0] = 1;
            
            Assert.Throws<BLSPrivateKeyException>(
                () => BLSInterface.ValidatePrivateKey(privateKey));
        }
        
        [Fact]
        public void LoadTestSuitePrivateKeys()
        {
            var files = Directory.GetFiles("../../../../tests/sign/");

            
            foreach (var file in files)
            {
                _testOutputHelper.WriteLine("Testing file: " + file);
                using FileStream fReader = File.OpenRead(file);
                using var sReader = new StreamReader(fReader);
                
                var testYaml = BLSTestBase.ParseTest(sReader);
                byte[] privateKey = new byte[]{ 0x00, };

                // MCL follows the system endianess, and test suite uses big endian.
                privateKey = HexUtil.ToBytes(testYaml.Input["privkey"]);

                if (privateKey.SequenceEqual(new byte[privateKey.Length]))
                {
                    Assert.Throws<BLSPrivateKeyException>(
                        () => BLSInterface.ValidatePrivateKey(privateKey));
                }
                else
                {
                    var result = BLSInterface.ValidatePrivateKey(privateKey);
                    Assert.True(result);
                    _testOutputHelper.WriteLine("Private key: " + BitConverter.ToString(privateKey));
                }
                _testOutputHelper.WriteLine("=====");
            }

        }
    }
}