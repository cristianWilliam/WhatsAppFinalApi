namespace WhatsAppFinalApi.Users;

public class UserImage(Guid userId, byte[] image)
{
    public Guid UserId { get; private set; } = userId;
    public byte[] Image { get; private set; } = image;

    public void UpdateImage(byte[] newImage)
    {
        Image = newImage;
    }
}