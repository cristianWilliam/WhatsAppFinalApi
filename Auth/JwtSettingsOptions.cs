namespace WhatsAppFinalApi.Auth;

public class JwtSettingsOptions
{
    public static string SessionName = "JwtSettings";
    public string Secret { get; set; } = "";
}