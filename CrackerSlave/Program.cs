// See https://aka.ms/new-console-template for more information

using CrackerMaster.model;
using CrackerSlave;
class Program
{
    public static void Main(string[] args)
    {
        List<UserInfoClearText> result = new List<UserInfoClearText>();
        Slave slave = new Slave();

        slave.Connect("10.200.130.55", 12345, result);


    }
}