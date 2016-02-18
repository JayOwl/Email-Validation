using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Web;
using System.Web.Services.Description;
using WebApplication1.ViewModels;

namespace WebApplication1.BusinessLogic
{
    public class Mailer
    {
        public const string SUCCESS
        = "Success! Your email has been sent.  Please allow up to 48 hrs for a reply.";
        //const string TO = "joel.r.benoit@gmail.com"; // Specify where you want this email sent.

        public string EmailFromArvixe(EmailMessage message)
        {
            const string FROM = "joel@jamped.com";
            const string FROM_PWD = "joelssd";
            const bool USE_HTML = true;
            const string SMTP_SERVER = "143.95.249.35";
           // const string FAKEURL = "@Html.Raw(ViewBag.FakeConfirmation)";


            try
            {
                MailMessage mailMsg = new MailMessage(FROM, message.Sender);
                mailMsg.Subject = message.Subject;                
                mailMsg.Body = message.Body + "<br/>sent by:"  + message.Sender;
               // mailMsg.Body = FAKEURL;
                mailMsg.IsBodyHtml = USE_HTML;

                SmtpClient smtp = new SmtpClient();
                smtp.Port = 25;
                smtp.Host = SMTP_SERVER;
                smtp.Credentials = new System.Net.NetworkCredential(FROM, FROM_PWD);
                smtp.Send(mailMsg);
            }
            catch (System.Exception ex)
            {
                return ex.Message;
            }
            return SUCCESS;
        }
    }

}