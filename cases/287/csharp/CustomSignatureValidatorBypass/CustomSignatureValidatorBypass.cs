using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ContosoApi.Authentication
{
    // Registers bearer-token authentication for the API. Targets .NET 8, where the
    // JWT bearer handler validates tokens through JsonWebTokenHandler by default.
    public static class JwtBearerSetup
    {
        public static IServiceCollection AddApiJwtBearer(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = configuration["Auth:Authority"];
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = configuration["Auth:Issuer"],
                        ValidateAudience = true,
                        ValidAudience = configuration["Auth:Audience"],
                        ValidateLifetime = true,
                    };

                    // A developer's attempt to "handle validation manually" after older
                    // clients sent tokens the default handler rejected. This parses the
                    // token and hands it back without ever checking its signature.
                    // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
                    options.TokenValidationParameters.SignatureValidator = (token, validationParameters) => new JsonWebToken(token);
                });

            return services;
        }
    }
}
