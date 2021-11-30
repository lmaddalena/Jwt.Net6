using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


// get the secret passphrase from config
string secretKey = builder.Configuration.GetSection("TokenAuthentication:SecretKey").Value;

// create the symmetrical key to sign and validate JWTs
var signingKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(secretKey));

// create the token validation parameters
var tokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
{
    // The signing key must match!
    ValidateIssuerSigningKey = true,                
    IssuerSigningKey = signingKey,
    // Validate the JWT Issuer (iss) claim
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration.GetSection("TokenAuthentication:Issuer").Value,
    // Validate the JWT Audience (aud) claim
    ValidateAudience = true,
    ValidAudience = builder.Configuration.GetSection("TokenAuthentication:Audience").Value,
    // Validate the token expiry
    ValidateLifetime = true,
    // If you want to allow a certain amount of clock drift, set that here
    ClockSkew = TimeSpan.Zero
};

// configure and add the middleware for supporting Authentication and Authorization.
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {  
        options.TokenValidationParameters = tokenValidationParameters; 
        });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
