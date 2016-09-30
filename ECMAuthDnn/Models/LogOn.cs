namespace Dnn.Modules.ECMAuthDnn.Models
{
    public class LogOn
    {
        public string UserName { get; set; }
        public string PassWord { get; set; }
        public bool RememberMe { get; set; } = true;

        public bool IsAuthenthicated { get; set; } = false;
    }
}