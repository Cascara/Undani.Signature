using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public class BlobHelper : Certificate
    {
        public BlobHelper(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey) : base(configuration, user, environmentId, publicKey) { }

        public string Start(string systemNames)
        {
            string content = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "|" + systemNames + "||";

            string[] aSystemNames = systemNames.Split(',');

            foreach (string systemName in aSystemNames)
            {
                SetSignStart(Guid.Parse(systemName.Substring(0, systemName.IndexOf('.'))), systemName.Substring(systemName.IndexOf('.') + 1), content);
            }

            return Convert.ToBase64String(GetHash(content));
        }

        private void SetSignStart(Guid id, string extension, string content)
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Set_SignStart", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier) { Value = id });
                    cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = EnvironmentId });
                    cmd.Parameters.Add(new SqlParameter("@Extension", SqlDbType.VarChar, 5) { Value = extension });
                    cmd.Parameters.Add(new SqlParameter("@Content", SqlDbType.VarChar, -1) { Value = content });
                    cmd.Parameters.Add(new SqlParameter("@DateTimeNow", SqlDbType.DateTime) { Value = DateTimeNow });

                    cmd.ExecuteNonQuery();

                    content = (string)cmd.Parameters["@Content"].Value;
                }
            }
        }

        public bool End(string systemNames, byte[] privateKeyBytes, char[] password, string digitalSignature)
        {
            string content = "||SignNumber:" + GetCrc32(DateTimeNow.ToString("dd/MM/yyyy")) + SerialNumber + "|" + systemNames + "||";

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

                using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("usp_Set_SignEnd", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.Add(new SqlParameter("@Id", SqlDbType.UniqueIdentifier));
                        cmd.Parameters.Add(new SqlParameter("@EnvironmentId", SqlDbType.UniqueIdentifier) { Value = EnvironmentId });
                        cmd.Parameters.Add(new SqlParameter("@UserId", SqlDbType.UniqueIdentifier) { Value = User.Id });
                        cmd.Parameters.Add(new SqlParameter("@SerialNumber", SqlDbType.VarChar, 100) { Value = SerialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100) { Value = Name });
                        cmd.Parameters.Add(new SqlParameter("@RFC", SqlDbType.VarChar, 13) { Value = RFC });
                        cmd.Parameters.Add(new SqlParameter("@CURP", SqlDbType.VarChar, 18) { Value = CURP });
                        cmd.Parameters.Add(new SqlParameter("@DigitalSignature", SqlDbType.VarChar, 1000) { Value = digitalSignature });
                        cmd.Parameters.Add(new SqlParameter("@DateTimeNow", SqlDbType.DateTime) { Value = DateTimeNow });

                        string[] aSystemNames = systemNames.Split(',');

                        Guid id;
                        foreach (string systemName in aSystemNames)
                        {
                            id = Guid.Parse(systemName.Substring(0, systemName.IndexOf('.')));

                            cmd.Parameters["@Id"].Value = id;

                            cmd.ExecuteNonQuery();

                            AddSign(
                            systemName,
                            chain,
                            pk,
                            DigestAlgorithms.SHA256,
                            PdfSigner.CryptoStandard.CMS,
                            Configuration["DataOwnerName"],
                            DateTimeNow);
                        }
                    }
                }                
            }

            return true;
        }

        private void AddSign(string systemName, X509Certificate[] chain, ICipherParameters pk, string digestAlgorithm, PdfSigner.CryptoStandard subfilter, string ownerName, DateTime date)
        {
            string codeVerify = GetCrc32(systemName) + "_" + date.Year.ToString();

            BoxCall boxCall = new BoxCall(Configuration, User);

            Stream source =  boxCall.DownloadWithTraceabilitySheet(systemName, codeVerify);

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
