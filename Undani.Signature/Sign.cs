using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Dynamic;
using System.Globalization;
using System.Xml.Serialization;

namespace Undani.Signature
{
    [XmlType("Sign")]
    public class Sign
    {

        [XmlElement("SerialNumber")]
        public Field SerialNumber;

        [XmlElement("InitialValidDate")]
        public Field InitialValidDate;

        [XmlElement("EndValidDate")]
        public Field EndValidDate;

        [XmlElement("Name")]
        public Field Name;

        [XmlElement("Reference")]
        public Field Reference;

        [XmlElement("PopulationUniqueIdentifier")]
        public Field PopulationUniqueIdentifier;

        [XmlElement("Represented")]
        public Field Represented;

        [XmlElement("DigitalSignature")]
        public Field DigitalSignature;

        [XmlElement("Date")]
        public Field Date;

        public Sign() { }

        public Sign(
            string settings,
            string serialNumber,
            DateTime initialValidDate,
            DateTime endValidDate,
            string name,
            string reference,
            string populationUniqueIdentifier,
            string represented,
            string digitalSignature,
            DateTime date
        )
        {
            dynamic dySettings = JsonConvert.DeserializeObject<ExpandoObject>(settings, new ExpandoObjectConverter());

            SerialNumber = new Field { Value = serialNumber, Description = dySettings.Sign.SerialNumber };
            InitialValidDate = new Field { Value = initialValidDate.ToString("d", new CultureInfo("es-ES")), Description = dySettings.Sign.InitialValidDate };
            EndValidDate = new Field { Value = endValidDate.ToString("d", new CultureInfo("es-ES")), Description = dySettings.Sign.EndValidDate };
            Name = new Field { Value = name, Description = dySettings.Sign.Name };
            Reference = new Field { Value = reference, Description = dySettings.Sign.Reference };
            PopulationUniqueIdentifier = new Field { Value = populationUniqueIdentifier, Description = dySettings.Sign.PopulationUniqueIdentifier };
            Represented = new Field { Value = represented, Description = dySettings.Sign.Represented };
            DigitalSignature = new Field { Value = digitalSignature, Description = dySettings.Sign.DigitalSignature };
            Date = new Field { Value = date.ToString("G", new CultureInfo("es-ES")), Description = dySettings.Sign.Date };
        }
    }
}
