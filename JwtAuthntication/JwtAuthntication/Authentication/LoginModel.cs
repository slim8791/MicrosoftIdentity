using System.ComponentModel.DataAnnotations;

namespace JwtAuthntication.Authentication
{
    public class LoginModel
    {
        [Required(ErrorMessage = "user name required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage = "Password required")]
        public string? Password { get; set; }
    }
}
