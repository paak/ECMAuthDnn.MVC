using System.Collections.Generic;
using System.Xml.Serialization;

namespace Dnn.Modules.ECMAuthDnn.Models
{
    [XmlType("AgentDetails")]
    public class AgentDetails
    {
        public int AgentID { get; set; } = -1;

        [XmlElement("Networks")]
        public List<CodeName> Networks { get; set; }

        [XmlArrayItem("Services")]
        public List<CodeName> Services { get; set; }
    }
}