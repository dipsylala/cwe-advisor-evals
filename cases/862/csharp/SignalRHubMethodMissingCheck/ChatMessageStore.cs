using System.Threading.Tasks;

namespace ChatApp.Hubs
{
    public class ChatMessage
    {
        public int Id { get; set; }
        public string RoomId { get; set; } = string.Empty;
        public string AuthorUserId { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
    }

    public interface IChatMessageStore
    {
        Task<ChatMessage> AddMessageAsync(string roomId, string authorUserId, string text);
        Task<ChatMessage?> GetMessageAsync(int messageId);
        Task DeleteMessageAsync(int messageId);
    }

    // EF Core-backed store in the real app; kept in-memory here for brevity.
    public class ChatMessageStore : IChatMessageStore
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, ChatMessage> _messages = new();
        private int _nextId = 1;

        public Task<ChatMessage> AddMessageAsync(string roomId, string authorUserId, string text)
        {
            var message = new ChatMessage
            {
                Id = System.Threading.Interlocked.Increment(ref _nextId),
                RoomId = roomId,
                AuthorUserId = authorUserId,
                Text = text
            };
            _messages[message.Id] = message;
            return Task.FromResult(message);
        }

        public Task<ChatMessage?> GetMessageAsync(int messageId)
        {
            _messages.TryGetValue(messageId, out var message);
            return Task.FromResult(message);
        }

        public Task DeleteMessageAsync(int messageId)
        {
            _messages.TryRemove(messageId, out _);
            return Task.CompletedTask;
        }
    }
}
