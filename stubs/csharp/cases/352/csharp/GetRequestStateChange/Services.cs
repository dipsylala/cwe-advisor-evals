// Compile-only collaborators the fixture references but does not ship (evals/stubs).
using System.Threading.Tasks;

namespace Storefront.Controllers
{
    public interface IAccountService
    {
        Task DeleteAccountAsync(string userId);
    }

    public interface IUserContext
    {
        string CurrentUserId { get; }
    }
}
