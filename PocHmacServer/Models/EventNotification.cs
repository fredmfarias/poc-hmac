using System;
using System.Collections.Generic;

namespace PocHmacServer.Models
{
    public class EventNotification
    {
        public string EntityId { get; set; }

        public string CompanyKey { get; set; }

        public string Name { get; set; }

        public DateTime Timestamp { get; set; }

        public Guid? CorrelationId { get; set; }

        public IDictionary<string, object> Metadata { get; set; }

        public Foo Data { get; set; }
    }
}
