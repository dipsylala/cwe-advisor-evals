namespace MultiFileRedisCommandRelay
{
    // Turns an AnnotationRecord into the key/value pair the cache layer will store.
    public class AnnotationCacheClient
    {
        private readonly RedisWireWriter _wireWriter;

        public AnnotationCacheClient(RedisWireWriter wireWriter)
        {
            _wireWriter = wireWriter;
        }

        public void StoreAnnotation(AnnotationRecord record)
        {
            string key = "annotation:" + record.DocumentId;
            string value = record.SavedAtUtc.ToString("O") + "|" + record.Text;

            _wireWriter.SendSetCommand(key, value);
        }
    }
}
