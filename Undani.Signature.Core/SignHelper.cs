using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Text;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class SignHelper : Certificate
    {
        public SignHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }
        
        public List<SignResult> Start(Guid elementInstanceRefId)
        {
            ActivityInstanceSignature activityInstanceSignature = new TrackingCall(Configuration, User).GetActivityInstanceSignature(elementInstanceRefId);

            JObject oJson = new FormCall(Configuration, User).GetJsonFormInstance(activityInstanceSignature.FormInstanceId);

            string formJsonPathRFC = new FormHelper(Configuration, User).GetJasonPathRFC(activityInstanceSignature.ElementId);

            if (formJsonPathRFC != string.Empty)
            {
                JToken jToken = oJson.SelectToken(formJsonPathRFC);
                ValidateSignatory((string)jToken);
            }
            else
                ValidateSignatory();

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Create_ElementInstance", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = activityInstanceSignature.RefId });
                    cmd.Parameters.Add(new SqlParameter("@FormInstanceId", SqlDbType.UniqueIdentifier) { Value = activityInstanceSignature.FormInstanceId });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = activityInstanceSignature.EnvironmentId });

                    cmd.ExecuteNonQuery();
                }

            }

            List<SignResult> signResults = new List<SignResult>();
            foreach (ElementSignature elementSignature in activityInstanceSignature.ElementsSignatures)
            {
                switch (elementSignature.ElementSignatureTypeId)
                {
                    case 1:
                        signResults.Add(new SignResult() { Key = elementSignature.Key, Template = elementSignature.Template, Type = elementSignature.ElementSignatureTypeId, Content = SetContentText(elementInstanceRefId, activityInstanceSignature.FormInstanceId, oJson, elementSignature) });
                        break;
                    case 2:
                        signResults.Add(new SignResult() { Key = elementSignature.Key, Template = elementSignature.Template, Type = elementSignature.ElementSignatureTypeId, Content = SetContentPDF(elementInstanceRefId, activityInstanceSignature.FormInstanceId, oJson, elementSignature) });
                        break;
                }
            }

            return signResults;
        }

        private string SetContentText(Guid elementInstanceRefId, Guid formInstanceId, JObject oJson, ElementSignature elementSignature)
        {
            JToken jToken;
            string content = "";            

            if (elementSignature.JsonPaths.Count == 1 && elementSignature.JsonPaths[0] == "/")
            {
                jToken = oJson.SelectToken("Integration");

                content = "||Formulario:" + formInstanceId.ToString() + "|Firmado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Contenido:" + JsonConvert.SerializeObject(jToken) + "||";
            }
            else
            {
                
                foreach (string jsonPath in elementSignature.JsonPaths)
                {
                    jToken = oJson.SelectToken(jsonPath);

                    elementSignature.Content = elementSignature.Content.Replace("[" + jsonPath + "]", (string)jToken);
                }

                content = "||Formulario:" + formInstanceId.ToString() + "|Firmado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Contenido:" + elementSignature.Content + "||";
            }

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_Document", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = elementSignature.Key });
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = Guid.Empty });
                    cmd.Parameters.Add(new SqlParameter("@Extension", SqlDbType.VarChar, 5) { Value = "" });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Value = content });
                    cmd.Parameters.Add(new SqlParameter("@Created", SqlDbType.DateTime) { Value = DateTimeNow });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }

            }

            return Convert.ToBase64String(GetHash(content));
        }

        private string SetContentPDF(Guid elementInstanceRefId, Guid formInstanceId, JObject oJson, ElementSignature elementSignature)
        {
            JToken jToken;
            string content = "";

            jToken = oJson.SelectToken(elementSignature.JsonPaths[0]);

            content = "||Formulario:" + formInstanceId.ToString() + "|Firmado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Documento:" + JsonConvert.SerializeObject(jToken) + "||";

            jToken = oJson.SelectToken(elementSignature.JsonPaths[0] + ".SystemName");

            string systemName = (string)jToken;

            Guid id = Guid.Parse(systemName.Substring(0, systemName.IndexOf('.')));

            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_Document", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = elementSignature.Key });
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
                    cmd.Parameters.Add(new SqlParameter("@Extension", SqlDbType.VarChar, 5) { Value = "PDF" });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Value = content });
                    cmd.Parameters.Add(new SqlParameter("@Created", SqlDbType.DateTime) { Value = DateTimeNow });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }

            }

            return Convert.ToBase64String(GetHash(content));
        }

        public bool SetSignText(Guid elementInstanceRefId, string key, string template, string digitalSignature)
        {
            ActivityInstanceSignature activityInstanceSignature = new TrackingCall(Configuration, User).GetActivityInstanceSignatureTemplate(elementInstanceRefId, template);

            string content = "";
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_DocumentContent", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }

            }

            bool valid = false;
            if (ValidateSeal(content, digitalSignature))
            {
                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_Sign", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = RFC });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@CURP", SqlDbType.VarChar, 18) { Value = CURP });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@Date", SqlDbType.DateTime) { Value = DateTimeNow });

                        Document document = new Document() { Id = activityInstanceSignature.FormInstanceId, EnvironmentId = activityInstanceSignature.EnvironmentId, ContentSigned = content };
                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                document.Signs.Add(new Sign()
                                {
                                    SerialNumber = reader.GetString(0),
                                    Name = reader.GetString(1),
                                    RFC = reader.GetString(2),
                                    CURP = reader.GetString(3),
                                    DigitalSignature = reader.GetString(4),
                                    Date = reader.GetDateTime(5)
                                });
                            }

                            string xml = new Xml<Document>().Serialize(document);
                            
                            dynamic templateResponse = new TemplateCall(Configuration, User).SignatureGraphicRepresentation(document.EnvironmentId, template, xml);

                            valid = new TrackingCall(Configuration, User).SetActivityInstanceDocumentSigned(elementInstanceRefId, key, new DocumentSigned());

                        }
                    }
                }
            }

            return valid;
        }

        public bool SetSignPDF(Guid elementInstanceRefId, string key, string template, byte[] privateKeyBytes, char[] password, string digitalSignature)
        {
            ActivityInstanceSignature activityInstanceSignature = new TrackingCall(Configuration, User).GetActivityInstanceSignatureTemplate(elementInstanceRefId, template);

            string content = "";
            Guid id = Guid.Empty;
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_DocumentContent", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                    id = (Guid)cmd.Parameters["@Id"].Value;
                }

            }

            bool valid = false;
            if (ValidateSeal(content, digitalSignature))
            {
                X509Certificate[] chain = new X509Certificate[1];

                chain[0] = new X509CertificateParser().ReadCertificate(PublicKey);

                ICipherParameters pk;
                try
                {
                    pk = PrivateKeyFactory.DecryptKey(password, privateKeyBytes);
                }
                catch (Exception)
                {
                    return false;
                }
                
                AddSign(
                    id.ToString() + ".pdf",
                    chain,
                    pk,
                    DigestAlgorithms.SHA256,
                    PdfSigner.CryptoStandard.CMS,
                    Configuration["DataOwnerName"],
                    DateTimeNow
                );

                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_Sign", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = RFC });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@CURP", SqlDbType.VarChar, 18) { Value = CURP });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@Date", SqlDbType.DateTime) { Value = DateTimeNow });

                        cmd.ExecuteNonQuery();

                        valid = new TrackingCall(Configuration, User).SetActivityInstanceDocumentSigned(elementInstanceRefId, key, new DocumentSigned());
                    }
                }
            }

            return valid;
        }

        private void AddSign(string systemName, X509Certificate[] chain, ICipherParameters pk, string digestAlgorithm, PdfSigner.CryptoStandard subfilter, string ownerName, DateTime date)
        {
            string codeVerify = GetCrc32(systemName) + "_" + date.Year.ToString();

            BoxCall boxCall = new BoxCall(Configuration, User);

            Stream source = boxCall.DownloadWithTraceabilitySheet(systemName, codeVerify);

            PdfReader reader = new PdfReader(source);

            PdfDocument document = new PdfDocument(reader);

            string fileTemp = System.IO.Path.GetTempFileName();

            FileStream signed = File.OpenWrite(fileTemp);

            PdfSigner signer = new PdfSigner(reader, signed, false);

            PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
                .SetReason(codeVerify)
                .SetLocation(ownerName)
                .SetPageNumber(document.GetNumberOfPages())
                .SetReuseAppearance(false);

            Rectangle rect = new Rectangle(80, 648, 450, 90);

            appearance
                .SetReasonCaption("Código de verificación: ")
                .SetLocationCaption("Organización: ")
                .SetPageRect(rect)
                .SetPageNumber(document.GetNumberOfPages());

            signer.SetFieldName(codeVerify);
            signer.SetSignDate(date);

            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm);

            signer.SignDetached(pks, chain, null, null, null, 0, subfilter);

            boxCall.Upload(systemName, fileTemp);
        }
    }
}
