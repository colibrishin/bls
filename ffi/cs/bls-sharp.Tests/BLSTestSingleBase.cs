using System;
using System.IO;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace bls_sharp.Tests
{
    public sealed class BLSTestSingleBase
    {
        public List<string> Input { get; set; }
        
        public string Output { get; set; }
        
        public static BLSTestSingleBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSTestSingleBase>(yaml);
        }
    }
}