using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityManager.Services
{
    public interface ITokenService
    {
        Task<ClaimsIdentity> GetIdentityAsync(string username, string password);

        Task<string> GenerateTokenAsync(string username, string password);


    }

}