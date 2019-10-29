using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;

namespace Undani.Signature
{
    [XmlType("Signs")]
    public class SignList
    {
        public SignList() { }

        [XmlAttribute("description")]
        public string Description;

        [XmlElement("Sign")]
        public List<Sign> Value;
    }
}
