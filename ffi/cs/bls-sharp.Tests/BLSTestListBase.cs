using System;
using System.IO;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace bls_sharp.Tests
{
    public sealed class BLSTestListBase
    {
        public Dictionary<string, List<string>> Input { get; set; }
        
        public string Output { get; set; }
        
        public static BLSTestListBase ParseTest(StreamReader yaml)
        {
            var deserializer = new DeserializerBuilder().
                WithNamingConvention(CamelCaseNamingConvention.Instance).
                Build();
            return deserializer.Deserialize<BLSTestListBase>(yaml);
        }
    }
}