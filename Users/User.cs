namespace WhatsAppFinalApi.Users;

public class User(Guid id, string name)
{
    public Guid Id { get; private set; } = id;
    public string Name { get; private set; } = name;
}