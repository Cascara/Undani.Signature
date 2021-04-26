using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Dynamic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
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

        [XmlElement("Certificate")]
        public Field Certificate;

        public Sign() { }

        public Sign(
            string settings,
            string serialNumber,
            string name,
            string reference,
            string populationUniqueIdentifier,
            string represented,
            string digitalSignature,
            DateTime date,
            string certificate
        )
        {
            string pkcs7 = certificate;
            pkcs7 = pkcs7.Replace("-----BEGIN PKCS7-----", "");
            pkcs7 = pkcs7.Replace("-----END PKCS7-----", "");

            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(Convert.FromBase64String(pkcs7));

            X509Certificate X509PublicKey = collection[0];

            DateTime initialValidDate;
            DateTime endValidDate;

            initialValidDate = DateTime.Parse(X509PublicKey.GetEffectiveDateString());

            endValidDate = DateTime.Parse(X509PublicKey.GetExpirationDateString());

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
            Certificate = new Field { Value = certificate, Description = dySettings.Sign.Certificate };
        }
    }
}
