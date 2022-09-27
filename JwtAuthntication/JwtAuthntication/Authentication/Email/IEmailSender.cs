namespace JwtAuthntication.Authentication.Email
{
    public interface IEmailSender
    {
        void SendEmail(Message message);
    }
}
