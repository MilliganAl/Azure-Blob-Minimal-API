using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;
using AzureBlobAPI;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Azure;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;


var builder = WebApplication.CreateBuilder(args);


string storageAccount = builder.Configuration["AzureStorageAccount"];
string container = builder.Configuration["AzureContainer"];
string connectionString = builder.Configuration["AzureConnectionString"];
string passowrd = builder.Configuration["StoreageAccountPassword"];
var blobServiceClient = new BlobServiceClient(connectionString);


builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
});


builder.Services.AddAuthorization();
var app = builder.Build();
app.UseHttpsRedirection();




#region Upload File
app.MapPost("/AzureBlob/UploadFile",  (IFormFile fileInformation, string targetFolder)  =>

{
    // Create a BlobServiceClient object by passing in the connection string
    BlobServiceClient blobServiceClient = new BlobServiceClient(connectionString);

    // Get a reference to the container
    BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(container);

    string uploads = Path.Combine("Uploads");
    //Create directory if it doesn't exist 
    Directory.CreateDirectory(uploads);
    
    string filePath = Path.Combine(uploads, fileInformation.FileName);
    using (Stream fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write))
    {
    fileInformation.CopyTo(fileStream);
    }

    string blobName = (targetFolder + fileInformation.FileName).Trim();

    BlobClient blobClient = containerClient.GetBlobClient(blobName);

    using (var fileStream1 = new FileStream(@"Uploads\" + fileInformation.FileName, FileMode.Open))
    {

        blobClient.Upload(fileStream1, true);

    }

    Directory.Delete(@"Uploads\", true);

    return Results.Ok(fileInformation.FileName);

}).RequireAuthorization();
#endregion Upload File



#region DownloadFile 
app.MapGet("AzureBlob/DownloadFile", async (string folderPath, string mimeType) =>
{

    BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(container);

    string localPath = Path.Combine("Uploads");

    Directory.CreateDirectory(localPath);

    string fileName = Path.GetFileName(folderPath);
    string localFilePath = Path.Combine(localPath, fileName);

    string downloadFilePath = localFilePath.Replace(Path.GetExtension(folderPath), Path.GetExtension(folderPath));

    Console.WriteLine("\nDownloading blob to\n\t{0}\n", downloadFilePath);

    BlobClient blobClient = containerClient.GetBlobClient(folderPath);

    await blobClient.DownloadToAsync(downloadFilePath);

    return  Results.File(Path.GetFullPath(localPath + @"\" + fileName), contentType: mimeType);

}).RequireAuthorization();
#endregion DownloadFile


app.MapGet("AzureBlob/GetBlobUrl", (string folderPath) =>
{

    BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(container);

    string localPath = Path.Combine("Uploads");


    var blobClient = containerClient.GetBlobClient(folderPath);

    // var a = containerClient.GetBlobClient(folderPath).GenerateSasUri().OriginalString;
    Azure.Storage.Sas.BlobSasBuilder blobSasBuilder = new Azure.Storage.Sas.BlobSasBuilder()
    {
        BlobContainerName = container.ToString(),  
        BlobName = folderPath,
        ExpiresOn = DateTime.UtcNow.AddMinutes(60),//Let SAS token expire after 5 minutes.,
        
    };
    blobSasBuilder.SetPermissions(Azure.Storage.Sas.BlobSasPermissions.Read);//User will only be able to read the blob and it's properties
    var sasToken = blobSasBuilder.ToSasQueryParameters(new StorageSharedKeyCredential(storageAccount.ToString(), passowrd.ToString())).ToString();

    var sasUrl = blobClient.Uri.AbsoluteUri + "?" + sasToken;


    return sasUrl;

}).RequireAuthorization();


#region Delete File
app.MapDelete("AzureBlob/DeleteFile", async (string folderPath, string mimeType) =>
{

    BlobContainerClient containerClient = blobServiceClient.GetBlobContainerClient(container);

    string localPath = Path.Combine("Uploads");

    Directory.CreateDirectory(localPath);



    string fileName = Path.GetFileName(folderPath);
    string localFilePath = Path.Combine(localPath, fileName);

    string downloadFilePath = localFilePath.Replace(Path.GetExtension(folderPath), Path.GetExtension(folderPath));

    Console.WriteLine("\nDownloading blob to\n\t{0}\n", downloadFilePath);

    BlobClient blobClient = containerClient.GetBlobClient(folderPath);

    await blobClient.DeleteAsync();


    return Results.File(Path.GetFullPath(localPath + @"\" + fileName), contentType: mimeType);

}).RequireAuthorization();


#endregion Delete File






#region Bearer Token 
app.MapPost("/security/createToken", [AllowAnonymous] (User user) =>
{
    if (user.UserName == builder.Configuration["ApiUserName"] && user.Password == builder.Configuration["ApiPassword"])
    {
        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var key = Encoding.ASCII.GetBytes
        (builder.Configuration["Jwt:Key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
             }),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials
            (new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha512Signature) 
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);
        var stringToken = tokenHandler.WriteToken(token);
        return Results.Ok(stringToken);
    }
    return Results.Unauthorized();
});

# endregion Bearer Token 


app.UseAuthentication();
app.UseAuthorization();
app.Run();