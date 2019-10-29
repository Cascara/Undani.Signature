using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Undani.Signature.Core.Resource
{
    public class Xml<T>
    {
        public string Serialize(T obj, Encoding encoding)
        {
            XmlSerializer xsSubmit = new XmlSerializer(typeof(T));
            string result = "";

            XmlWriterSettings settings = new XmlWriterSettings()
            {
                Encoding = new UnicodeEncoding(false, false), //no BOM in a .NET string
                Indent = false,
                OmitXmlDeclaration = false
            };

            using (var sww = new StringWriterWithEncoding(encoding))
            {
                using (XmlWriter writer = XmlWriter.Create(sww, settings))
                {
                    xsSubmit.Serialize(writer, obj);
                    result = sww.ToString();
                }
            }

            return result;
        }
    }
}
