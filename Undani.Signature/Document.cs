using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class Document
    {
        public string ProcedureName { get; set; }
        public Guid FormInstanceId { get; set; }
        public Guid SystemName { get; set; }
        public string OriginalName { get; set; }
        public string Content { get; set; }
        public string OwnerName { get; set; }
        public string DocumentSignedSettings { get; set; }
        public Guid EnvironmentId { get; set; }
        public DateTime Created { get; set; }
    }
}
