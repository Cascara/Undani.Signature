using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Undani.Signature.Core.Resource
{
    public class Xml<T>
    {
        public string Serialize(T obj)
        {
            XmlSerializer xsSubmit = new XmlSerializer(typeof(T));
            string result = "";

            using (var sww = new StringWriter())
            {
                using (XmlWriter writer = XmlWriter.Create(sww))
                {
                    xsSubmit.Serialize(writer, obj);
                    result = sww.ToString();
                }
            }

            return result;
        }
    }
}
