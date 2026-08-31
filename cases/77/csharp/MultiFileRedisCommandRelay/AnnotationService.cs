using System;

namespace MultiFileRedisCommandRelay
{
    public class AnnotationService
    {
        private readonly AnnotationCacheClient _cacheClient;

        public AnnotationService(AnnotationCacheClient cacheClient)
        {
            _cacheClient = cacheClient;
        }

        // Wraps the raw note text with save metadata before handing it to the cache layer.
        public void SaveAnnotation(string documentId, string noteText)
        {
            var record = new AnnotationRecord
            {
                DocumentId = documentId,
                Text = noteText ?? string.Empty,
                SavedAtUtc = DateTime.UtcNow
            };

            _cacheClient.StoreAnnotation(record);
        }
    }

    public class AnnotationRecord
    {
        public string DocumentId { get; set; }
        public string Text { get; set; }
        public DateTime SavedAtUtc { get; set; }
    }
}
