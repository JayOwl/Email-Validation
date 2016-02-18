using System;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.ViewModels
{
    public class EmailMessage
    {
        [Display(Name = "Your email address")]
        [Required(ErrorMessage = "An email address is required.")]
        [RegularExpression(@"^(([^<>()[\]\\.,;:\s@\""]+"
                + @"(\.[^<>()[\]\\.,;:\s@\""]+)*)|(\"".+\""))@"
                + @"((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
                + @"\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+"
                + @"[a-zA-Z]{2,}))$", ErrorMessage = "Not a valid email address")]
        public string Sender { get; set; }
        [Required]
        public string Subject { get; set; }
        [Display(Name = "Message")]
        [Required]
        public string Body { get; set; }

        public EmailMessage() { }
        public EmailMessage(string sender, string subject, string body)
        {
            Sender = sender;
            Subject = subject;
            Body = body;
        }
    }
}
