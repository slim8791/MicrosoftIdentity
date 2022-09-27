using System.ComponentModel.DataAnnotations;

namespace JwtAuthntication.Authentication
{
    public class LoginModel
    {
        [Required(ErrorMessage = "user name required")]
        public string? UserName { get; set; }
        public string? email { get; set; }
        [Required(ErrorMessage = "Password required")]
        public string? Password { get; set; }
    }

    public class ResetPasswordModel : LoginModel
    {

    }
    public class EmailResetPasswordModel: ResetPasswordModel
    {
        public string token { get; set; }
    }
    public class ChangePasswordModel : LoginModel
    {
        [Required(ErrorMessage = "Password required")]
        public string NewPassword { get; set; }
    }
}
