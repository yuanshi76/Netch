namespace Netch.Models;

public class MessageException : Exception
{
    public MessageException()
    {
    }

    public MessageException(string message) : base(message)
    {
    }

    public MessageException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
