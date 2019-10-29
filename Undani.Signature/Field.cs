using System.Xml.Serialization;

namespace Undani.Signature
{
    public class Field
    {
        [XmlAttribute("description")]
        public string Description;

        [XmlText]
        public string Value;
    }
}
