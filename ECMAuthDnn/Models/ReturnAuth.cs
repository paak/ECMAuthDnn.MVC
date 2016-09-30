using System.Xml.Serialization;

namespace Dnn.Modules.ECMAuthDnn.Models
{
    [XmlType("AuthResponseDTO")]
    public class AuthResponseDTO
    {
        public UserDetails UserDetails { get; set; }
        public AgentDetails AgentDetails { get; set; }
    }
}