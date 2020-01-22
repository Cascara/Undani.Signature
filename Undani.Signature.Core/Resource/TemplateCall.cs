using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;

namespace Undani.Signature.Core.Resource
{
    internal class TemplateCall : Call
    {
        public TemplateCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public List<ActivityInstanceDocumentSigned> SignatureGraphicRepresentation(Guid procedureInstanceRefId, string key, Guid systemName, string originalName, string template, string xml)
        {

            dynamic message = new
            {
                Action = "GraphicRepresentation",
                SAID = Guid.Empty,
                MessageBody = new
                {
                    OriginalName = originalName,
                    SystemName = systemName,
                    DocumentType = template,
                    Xml = xml
                }
            };

            var queueClient = ClientBus.Bus.Connect(Configuration["CnSrvBus"], "template");

            queueClient.Send(message);

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_DocumentGraphicRepresentationMessage", cn) { CommandType = CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@GraphicRepresentationMessage", SqlDbType.VarChar, -1) { Value = JsonConvert.SerializeObject(message) });

                    cmd.ExecuteNonQuery();
                }
            }

            List<ActivityInstanceDocumentSigned> response = new List<ActivityInstanceDocumentSigned>();

            response.Add(new ActivityInstanceDocumentSigned() { OriginalName = originalName + ".pdf", SystemName = systemName.ToString() + ".pdf", HashCode = "", Created = false });
            response.Add(new ActivityInstanceDocumentSigned() { OriginalName = originalName + ".xml", SystemName = systemName.ToString() + ".xml", HashCode = "", Created = true });

            return response;
        }
    }
}
