﻿using System.Xml.Serialization;

namespace Dnn.Modules.ECMAuthDnn.Models
{
    [XmlType("UserDetails")]
    public class UserDetails
    {
        public int AgentID { get; set; } = -1;
        public int ContactID { get; set; } = -1;

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
    }
}