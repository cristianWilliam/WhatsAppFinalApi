using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;

namespace WhatsAppFinalApi.Users;

[ApiController, Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpGet]
    public IActionResult GetUsers()
    {
        return Ok(UserFakeDb.Users);
    }

    [HttpPut("{userId}/image")]
    public async Task<IActionResult> UpdateImage(Guid userId, [FromForm] IFormFile file)
    {
        var memoryStream = new MemoryStream();
        await file.CopyToAsync(memoryStream);

        var userImage = UserFakeDb.UserImages
            .FirstOrDefault(userImage => userImage.UserId == userId);
        
        if (userImage is null)
            UserFakeDb.UserImages
                .Add(new UserImage(userId, memoryStream.ToArray()));
        else
            userImage.UpdateImage(memoryStream.ToArray());

        return Ok();
    }

    [HttpGet("{userId}/image")]
    public IActionResult GetUserImage(Guid userId)
    {
        var userImage = UserFakeDb.UserImages
            .FirstOrDefault(image => image.UserId == userId);
        
        if (userImage is null)
            return NotFound();

        return File(userImage.Image, "image/png");
    }
}