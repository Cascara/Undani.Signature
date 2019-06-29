using System;
using System.Collections.Generic;

namespace Undani.Signature
{
    public class DocumentSigned
    {
        public DocumentSigned()
        {
            Signs = new List<Sign>();
        }

        public Guid Id { get; set; }
        public Guid EnvironmentId { get; set; }
        public DateTime Created { get; set; }
        public string ContentSigned { get; set; }
        public List<Sign> Signs { get; set; }
    }
}
