using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace WhatsAppFinalApi.Messages;

[Authorize]
public class MessageHub : Hub
{
    private string CurrentUser => Context.User!
        .FindFirst(ClaimTypes.NameIdentifier)!.Value;
    
    public Task SendMessage(Guid destinationUserId, string message)
    {
        var data = new
        {
            userId = CurrentUser,
            message
        };
        
        var destinationUserUpper = destinationUserId.ToString().ToUpperInvariant();
        return Clients.User(destinationUserUpper)
            .SendAsync("message-received", data);
    }
}