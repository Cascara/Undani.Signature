using System;
using System.Collections.Generic;
using System.Text;

namespace Undani.Signature
{
    public class ActivityInstanceSignature
    {
        public Guid RefId { get; set; }
        public Guid FormInstanceId { get; set; }
        public string ElementId { get; set; }
        public Guid EnvironmentId { get; set; }
        public List<ElementSignature> ElementsSignatures { get; set; }
    }
}
