using CourseManagement.ViewModels;

namespace CourseManagement.Services
{
    public interface IUsersService
    {
        Task<string> Authenticate(LoginRequest request);

        Task<bool> Register(RegisterRequest request);
    }
}