using System;
using System.IO;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace bls_sharp.Tests
{
    public sealed class BLSTestBase
    {
        public Dictionary<string, string> Input { get; set; }
        
        public string Output { get; set; }
        
        public static BLSTestBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSTestBase>(yaml);
        }
    }
}