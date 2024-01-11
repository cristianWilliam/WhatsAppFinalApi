namespace WhatsAppFinalApi.Users;

public static class UserFakeDb
{
    public static readonly List<User> Users =
    [
        new User(new Guid("0C08FE0C-4CB1-4D2B-87B4-CFC580910AC6"), "Harry Potter"),
        new User(new Guid("A24B4213-2F40-4661-A6D5-C65AA6685AB4"), "Albus Dumbledore"),
        new User(new Guid("5273A86D-6EA2-4C42-9B5D-573B75367FBF"), "Lord Voldemort")
    ];

    public static readonly List<UserImage> UserImages = [];
}