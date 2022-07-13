using System.ComponentModel.DataAnnotations;

namespace JwtAuthntication.Authentication
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "user name required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage = "password required")]
        public string? Password { get; set; }
        [EmailAddress]
        [Required(ErrorMessage = "email required")]
        public string? Email { get; set; }
    }
}
