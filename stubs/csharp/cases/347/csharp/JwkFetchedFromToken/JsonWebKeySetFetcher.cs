// Compile-only collaborator the fixture references but does not ship (evals/stubs).
using Microsoft.IdentityModel.Tokens;

namespace EvalCases
{
    public static class JsonWebKeySetFetcher
    {
        public static JsonWebKeySet Fetch(string jkuUrl) => new JsonWebKeySet();
    }
}
