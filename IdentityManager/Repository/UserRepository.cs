using System.Threading.Tasks;

namespace IdentityManager.Respository
{
    public class UserRepository : IUserRepository
    {
        public async Task<bool> LogInAsync(string username, string password)
        {
            await Task.Delay(10);

            if(username == "TEST" && password == "TEST123")
                return true;
            else
                return false;
        }
    }

}