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
using Microsoft.Data.SqlClient;
using System.IO;
using System.Text;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class SignHelper : Certificate
    {
        public SignHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public List<ContentSigned> Start(Guid procedureInstanceRefId, Guid elementInstanceRefId, List<string> templates)
        {
            ValidateRevocation();

            ActivityInstanceSignature activityInstanceSignature = new TrackingCall(Configuration, User).GetActivityInstanceSignature(elementInstanceRefId);

            JObject oJson = new FormCall(Configuration, User).GetJsonFormInstance(activityInstanceSignature.FormInstanceId);

            string formJsonPathReference = new FormHelper(Configuration, User).GetJasonPathReference(activityInstanceSignature.ElementId);

            if (formJsonPathReference != string.Empty)
            {
                JToken jToken = oJson.SelectToken(formJsonPathReference);
                ValidateSignatory((string)jToken);
            }
            else
                ValidateSignatory();

            List<ContentSigned> signResults = new List<ContentSigned>();
            foreach (ElementSignature elementSignature in activityInstanceSignature.ElementsSignatures)
            {
                if (templates.Contains(elementSignature.Template))
                {
                    switch (elementSignature.ElementSignatureTypeId)
                    {
                        case 1:
                            signResults.Add(new ContentSigned()
                            {
                                Key = elementSignature.Key,
                                Template = elementSignature.Template,
                                Type = elementSignature.ElementSignatureTypeId,
                                Content = SetContentText(
                                    procedureInstanceRefId,
                                    activityInstanceSignature.OwnerId,
                                    activityInstanceSignature.EnvironmentId,
                                    activityInstanceSignature.ProcedureName,
                                    activityInstanceSignature.FormInstanceId,
                                    oJson,
                                    elementSignature
                                )
                            });
                            break;
                        case 2:
                            signResults.Add(new ContentSigned() 
                            { 
                                Key = elementSignature.Key, 
                                Template = elementSignature.Template, 
                                Type = elementSignature.ElementSignatureTypeId, 
                                Content = SetContentPDF(
                                    procedureInstanceRefId, 
                                    activityInstanceSignature.OwnerId, 
                                    activityInstanceSignature.EnvironmentId, 
                                    activityInstanceSignature.ProcedureName, 
                                    activityInstanceSignature.FormInstanceId, 
                                    oJson, 
                                    elementSignature
                                ) 
                            });
                            break;
                    }
                }
            }

            return signResults;
        }

        private string SetContentText(Guid procedureInstanceRefId, Guid ownerId, Guid environmentId, string procedureName, Guid formInstanceId, JObject oJson, ElementSignature elementSignature)
        {
            string content = "";

            if (elementSignature.Create)
            {
                DeleteDocument(procedureInstanceRefId, elementSignature.Key);

                JToken jToken;

                if (elementSignature.JsonPaths.Count == 1 && elementSignature.JsonPaths[0] == "/")
                {
                    jToken = oJson.SelectToken("Integration");

                    content = "||Documento:" + formInstanceId.ToString() + "/" + environmentId.ToString() + "|Creado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Contenido:" + JsonConvert.SerializeObject(jToken) + "||";
                }
                else
                {

                    foreach (string jsonPath in elementSignature.JsonPaths)
                    {
                        jToken = oJson.SelectToken(jsonPath);

                        elementSignature.Content = elementSignature.Content.Replace("[" + jsonPath + "]", (string)jToken);
                    }

                    content = "||Documento:" + formInstanceId.ToString() + "/" + environmentId.ToString() + "|Creado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Contenido:" + elementSignature.Content + "||";
                }
            }

            content = SetDocument(procedureInstanceRefId, elementSignature.Key, procedureName, formInstanceId, ownerId, environmentId, Guid.NewGuid(), elementSignature.OriginalName, "", content);

            return Convert.ToBase64String(GetHash(content));
        }

        private string SetContentPDF(Guid procedureInstanceRefId, Guid ownerId, Guid environmentId, string procedureName, Guid formInstanceId, JObject oJson, ElementSignature elementSignature)
        {
            string content = "";
            Guid systemName = Guid.Empty;

            if (elementSignature.Create)
            {
                JToken jToken;

                jToken = oJson.SelectToken(elementSignature.JsonPaths[0]);

                content = "||Documento:" + formInstanceId.ToString() + "/" + environmentId.ToString() + "|Creado:" + DateTimeNow.ToString("dd/MM/yyyy hh:mm:ss") + "|Documento:" + JsonConvert.SerializeObject(jToken) + "||";

                jToken = oJson.SelectToken(elementSignature.JsonPaths[0] + ".SystemName");

                string sSystemName = (string)jToken;

                systemName = Guid.Parse(sSystemName.Substring(0, sSystemName.IndexOf('.')));
            }

            content = SetDocument(procedureInstanceRefId, elementSignature.Key, procedureName, formInstanceId, ownerId, environmentId, systemName, elementSignature.OriginalName, "PDF", content);

            return Convert.ToBase64String(GetHash(content));
        }

        public string SetDocument(Guid procedureInstanceRefId, string key, string procedurename, Guid formInstanceId, Guid ownerId, Guid environmentId, Guid systemName, string originalName, string extension, string content)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_Document", cn) { CommandType = CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@ProcedureName", SqlDbType.VarChar, 250) { Value = procedurename });
                    cmd.Parameters.Add(new SqlParameter("@FormInstanceId", SqlDbType.UniqueIdentifier) { Value = formInstanceId });
                    cmd.Parameters.Add(new SqlParameter("@OwnerId", SqlDbType.UniqueIdentifier) { Value = ownerId });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = environmentId });
                    cmd.Parameters.Add(new SqlParameter("@SystemName", SqlDbType.UniqueIdentifier) { Value = systemName });
                    cmd.Parameters.Add(new SqlParameter("@OriginalName", SqlDbType.VarChar, 250) { Value = originalName });
                    cmd.Parameters.Add(new SqlParameter("@Extension", SqlDbType.VarChar, 5) { Value = extension });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Value = content, Direction = ParameterDirection.InputOutput });
                    cmd.Parameters.Add(new SqlParameter("@Created", SqlDbType.DateTime) { Value = DateTimeNow });

                    cmd.ExecuteNonQuery();

                    return (string)cmd.Parameters["@Content"].Value;
                }

            }
        }

        public void DeleteDocument(Guid procedureInstanceRefId, string key)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Delete_Document", cn) { CommandType = CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public bool SetSignText(Guid procedureInstanceRefId, Guid elementInstanceRefId, string key, string template, string represented, string digitalSignature)
        {
            Document document = GetDocument(procedureInstanceRefId, key);

            bool valid = false;
            if (ValidateSeal(document.Content, digitalSignature))
            {
                if (SignExists(procedureInstanceRefId, key))
                    return true;

                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_Sign", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                        cmd.Parameters.Add(new SqlParameter("@Reference", SqlDbType.VarChar, 50) { Value = Reference });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@PopulationUniqueIdentifier", SqlDbType.VarChar, 100) { Value = PopulationUniqueIdentifier });
                        cmd.Parameters.Add(new SqlParameter("@Represented", SqlDbType.VarChar, 500) { Value = represented });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Date", SqlDbType.DateTime) { Value = DateTimeNow });
                        cmd.Parameters.Add(new SqlParameter("@Certificate", SqlDbType.VarChar, 5000) { Value = GetPKCS7() });

                        DocumentSigned documentSigned = new DocumentSigned(document.DocumentSignedSettings, document.OwnerName, document.OriginalName, document.FormInstanceId, document.EnvironmentId, document.Created, document.Content);

                        using (SqlDataReader reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                documentSigned.Signs.Value.Add(new Sign(document.DocumentSignedSettings, reader.GetString(0), BeginningDate, ExpirationDate, reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetDateTime(6), reader.GetString(7)));
                            }


                            if (template.Contains("NoApply_"))
                            {
                                return true;
                            }
                            else if (template.Contains("OnlyProcedure_"))
                            {
                                string xml = new Xml<DocumentSigned>().Serialize(documentSigned, Encoding.UTF8);
                                List<ActivityInstanceDocumentSigned> activityInstanceDocumentsSigned = new TemplateCall(Configuration, User).SignatureGraphicRepresentation(procedureInstanceRefId, key, document.SystemName, document.OriginalName, template.Replace("OnlyProcedure_", ""), xml);
                                valid = new TrackingCall(Configuration, User).SetProcedureInstanceDocumentsSigned(procedureInstanceRefId, key, activityInstanceDocumentsSigned);
                            }
                            else
                            {
                                string xml = new Xml<DocumentSigned>().Serialize(documentSigned, Encoding.UTF8);
                                List<ActivityInstanceDocumentSigned> activityInstanceDocumentsSigned = new TemplateCall(Configuration, User).SignatureGraphicRepresentation(procedureInstanceRefId, key, document.SystemName, document.OriginalName, template, xml);
                                valid = new TrackingCall(Configuration, User).SetActivityInstanceDocumentsSigned(elementInstanceRefId, key, activityInstanceDocumentsSigned);
                            }

                        }
                    }
                }
            }
            else
            {
                throw new Exception("S510");
            }

            return valid;
        }


        public bool SetSignPDF(Guid procedureInstanceRefId, Guid elementInstanceRefId, string key, string template,  string represented,byte[] privateKeyBytes, char[] password,  string digitalSignature)
        {
            Document document = GetDocument(procedureInstanceRefId, key);

            bool valid = false;
            if (ValidateSeal(document.Content, digitalSignature))
            {
                if (SignExists(procedureInstanceRefId, key))
                    return true;

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
                    document.SystemName.ToString() + ".pdf",
                    chain,
                    pk,
                    DigestAlgorithms.SHA256,
                    PdfSigner.CryptoStandard.CMS,
                    represented,
                    DateTimeNow
                );

                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_Sign", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                        cmd.Parameters.Add(new SqlParameter("@Reference", SqlDbType.VarChar, 50) { Value = Reference });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@PopulationUniqueIdentifier", SqlDbType.VarChar, 100) { Value = PopulationUniqueIdentifier });
                        cmd.Parameters.Add(new SqlParameter("@Represented", SqlDbType.VarChar, 500) { Value = represented });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@ElementInstanceRefId", SqlDbType.UniqueIdentifier) { Value = elementInstanceRefId });
                        cmd.Parameters.Add(new SqlParameter("@Date", SqlDbType.DateTime) { Value = DateTimeNow });
                        cmd.Parameters.Add(new SqlParameter("@Certificate", SqlDbType.VarChar, 5000) { Value = GetPKCS7() });

                        cmd.ExecuteNonQuery();

                        List<ActivityInstanceDocumentSigned> activityInstanceDocumentsSigned = new List<ActivityInstanceDocumentSigned>();

                        activityInstanceDocumentsSigned.Add(new ActivityInstanceDocumentSigned() { SystemName = document.SystemName.ToString() + ".pdf", OriginalName = document.OriginalName, HashCode = "", Created = true });

                        valid = new TrackingCall(Configuration, User).SetActivityInstanceDocumentsSigned(elementInstanceRefId, key, activityInstanceDocumentsSigned);
                    }
                }
            }
            else
            {
                throw new Exception("S510");
            }

            return valid;
        }

        private bool SignExists(Guid procedureInstanceRefId, string key)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_SignExists", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@Reference", SqlDbType.VarChar, 50) { Value = Reference });
                    cmd.Parameters.Add(new SqlParameter("@Exists", SqlDbType.Bit) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (bool)cmd.Parameters["@Exists"].Value;
                }

            }
        }

        private Document GetDocument(Guid procedureInstanceRefId, string key)
        {
            Document document = new Document();
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_Document", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@ProcedureInstanceRefId", SqlDbType.UniqueIdentifier) { Value = procedureInstanceRefId });
                    cmd.Parameters.Add(new SqlParameter("@Key", SqlDbType.VarChar, 50) { Value = key });
                    cmd.Parameters.Add(new SqlParameter("@ProcedureName", SqlDbType.VarChar, 250) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@FormInstanceId", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@SystemName", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@OriginalName", SqlDbType.VarChar, 250) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@OwnerName", SqlDbType.VarChar, 500) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@DocumentSignedSettings", SqlDbType.VarChar, 1000) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output });
                    cmd.Parameters.Add(new SqlParameter("@Created", SqlDbType.DateTime) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    document.ProcedureName = (string)cmd.Parameters["@ProcedureName"].Value;
                    document.FormInstanceId = (Guid)cmd.Parameters["@FormInstanceId"].Value;
                    document.SystemName = (Guid)cmd.Parameters["@SystemName"].Value;
                    document.OriginalName = (string)cmd.Parameters["@OriginalName"].Value;
                    document.Content = (string)cmd.Parameters["@Content"].Value;
                    document.OwnerName = (string)cmd.Parameters["@OwnerName"].Value;
                    document.DocumentSignedSettings = (string)cmd.Parameters["@DocumentSignedSettings"].Value;
                    document.EnvironmentId = (Guid)cmd.Parameters["@EnvironmentId"].Value;
                    document.Created = (DateTime)cmd.Parameters["@Created"].Value;
                }

            }

            return document;
        }

        private void AddSign(string systemName, X509Certificate[] chain, ICipherParameters pk, string digestAlgorithm, PdfSigner.CryptoStandard subfilter, string ownerName, DateTime date)
        {
            string codeVerify = GetCrc32(systemName) + "_" + date.Year.ToString();

            BoxCall boxCall = new BoxCall(Configuration, User);

            Stream source = boxCall.DownloadWithTraceabilitySheet(systemName, codeVerify);

            string fileTemp = "";
            using (PdfReader reader = new PdfReader(source))
            {
                PdfDocument document = new PdfDocument(reader);

                fileTemp = System.IO.Path.GetTempFileName();

                FileStream signed = File.OpenWrite(fileTemp);

                PdfSigner signer = new PdfSigner(reader, signed, false);

                Rectangle rect = new Rectangle(55, 648, 500, 90);

                PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
                    .SetReason(codeVerify)
                    .SetLocation(ownerName)
                    .SetPageNumber(document.GetNumberOfPages())
                    .SetReuseAppearance(false)
                    .SetReasonCaption("Código de verificación: ")
                    .SetLocationCaption("Representada: ")
                    .SetPageRect(rect);

                signer.SetFieldName(Reference);
                signer.SetSignDate(date);

                IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm);

                signer.SignDetached(pks, chain, null, null, null, 0, subfilter);
            }

            boxCall.Upload(systemName, fileTemp);
        }

    }
}
