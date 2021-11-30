using System.Threading.Tasks;

namespace IdentityManager.Respository
{
    public interface IUserRepository
    {
        Task<bool> LogInAsync(string username, string password);

    }
}