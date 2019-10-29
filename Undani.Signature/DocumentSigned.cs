using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Xml.Serialization;

namespace Undani.Signature
{
    [XmlRoot("DocumentSigned")]
    public class DocumentSigned
    {

        [XmlElement("Entity")]
        public Field Entity;

        [XmlElement("Subject")]
        public Field Subject;

        [XmlElement("Id")]
        public Field Id;

        [XmlElement("EnvironmentId")]
        public Field EnvironmentId;

        [XmlElement("Created")]
        public Field Created;

        [XmlElement("ContentSigned")]
        public Field ContentSigned;

        [XmlElement("Signs")]
        public SignList Signs;

        public DocumentSigned() { }

        public DocumentSigned(
            string settings,
            string entity,
            string name,
            Guid id,
            Guid environmentId,
            DateTime created,
            string contentSigned
        )
        {
            dynamic dySettings = JsonConvert.DeserializeObject<ExpandoObject>(settings, new ExpandoObjectConverter());

            Entity = new Field { Value = entity, Description = dySettings.DocumentSigned.Entity };
            Subject = new Field { Value = name, Description = dySettings.DocumentSigned.Subject };
            Id = new Field { Value = id.ToString().ToUpper(), Description = dySettings.DocumentSigned.Id };
            EnvironmentId = new Field { Value = environmentId.ToString().ToUpper(), Description = dySettings.DocumentSigned.EnvironmentId };
            Created = new Field { Value = created.ToString("G", new CultureInfo("es-ES")), Description = dySettings.DocumentSigned.Created };
            ContentSigned = new Field { Value = contentSigned, Description = dySettings.DocumentSigned.ContentSigned };
            Signs = new SignList() { Description = dySettings.DocumentSigned.Signs, Value = new List<Sign>() };
        }
    }
}
