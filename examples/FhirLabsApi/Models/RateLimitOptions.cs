namespace FhirLabsApi.Models
{
    public class RateLimitOptions
    {
        public const string RateLimit = "RateLimit";
        public int PermitLimit { get; set; } = 40;
        public int Window { get; set; } = 10;
        public int ReplenishmentPeriod { get; set; } = 3;
        public int QueueLimit { get; set; } = 10;
        public int SegmentsPerWindow { get; set; } = 8;
        public int TokenLimit { get; set; } = 10;
        public int TokenLimit2 { get; set; } = 60;
        public int TokensPerPeriod { get; set; } = 10;
        public bool AutoReplenishment { get; set; } = true;
    }
}
