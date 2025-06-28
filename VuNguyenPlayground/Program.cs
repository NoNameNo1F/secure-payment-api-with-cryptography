using VuNguyenPlayground;

var timestamp1 = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
var partnerCode = "pc-1234567890";

var standards = RSASHA256.Import(partnerCode, timestamp1, null);
var (blockData, blockSign) = standards.HashBlock();
Console.WriteLine($"Block Data: \n\r {blockData}");
Console.WriteLine($"Block Data: \n\r {blockSign}");
if (standards.Verify(blockData, blockSign))
{
    Console.WriteLine("Verify success");
}
else
{
    Console.WriteLine("Verify failed");
}