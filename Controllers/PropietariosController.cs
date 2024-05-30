using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using ApiNueva.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MailKit.Net.Smtp;
using MimeKit;
using System.Text;

namespace ApiNueva.Controllers
{
    [Route("[controller]")]
	[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
	[ApiController]
	public class PropietariosController : ControllerBase
	{
		private readonly DataContext contexto;
		private readonly IConfiguration configuracion;
		private readonly IWebHostEnvironment environment;
		

		public PropietariosController(DataContext contexto, IConfiguration configuracion, IWebHostEnvironment env)
		{
			this.contexto = contexto;
			this.configuracion = configuracion;
			environment = env;
			
		}

		// POST: Propietarios/Login
		[HttpPost("login")]
		[AllowAnonymous]
		public ActionResult Login([FromForm] LoginView loginView)
		{
			try
			{
				string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
					password: loginView.Clave,
					salt: System.Text.Encoding.ASCII.GetBytes(configuracion["Salt"]!),
					prf: KeyDerivationPrf.HMACSHA1,
					iterationCount: 1000,
					numBytesRequested: 256 / 8
				));

				var propietario = contexto.Propietarios.FirstOrDefault(x => x.Email == loginView.Email);
				if (propietario == null || hashed != propietario!.Password)
				{
					return BadRequest("Usuario y/o clave incorrecta");
				}
				else
				{
					string secretKey = configuracion["TokenAuthentication:SecretKey"] ?? throw new ArgumentNullException(nameof(secretKey));
					var securityKey = secretKey != null ? new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secretKey)) : null;
					var credenciales = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
					var claims = new List<Claim>
					{
						new Claim(ClaimTypes.Name, propietario.Email),
						new Claim("Id", propietario.Id.ToString())
					};

					var token = new JwtSecurityToken(
						issuer: configuracion["TokenAuthentication:Issuer"],
						audience: configuracion["TokenAuthentication:Audience"],
						claims: claims,
						expires: DateTime.Now.AddMinutes(60),
						signingCredentials: credenciales
					);

					return Ok(new JwtSecurityTokenHandler().WriteToken(token));
				}

			}
			catch (Exception ex)
			{
				return BadRequest(ex.Message);
			}
		}


		// GET: Propietarios/Perfil
		[HttpGet("Perfil")]
		[Authorize]
		 public async Task<ActionResult<Propietario>> GetPerfil()
    {
       try
       {
        var mail = User.Identity!.Name;
        var propietario = await contexto.Propietarios.SingleOrDefaultAsync(p => p.Email == mail);
		propietario!.Password = "";
        return Ok(propietario);
       }
       catch(Exception e)
       {
        return BadRequest(e);
       }
    }
		
		// POST: Propietarios/Editar
		[HttpPut("Editar")]
		[Authorize]
		public IActionResult PutPropietario(Propietario propietario)
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);
				var propietarioDb = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (propietarioDb == null) return NotFound();

				if (propietario.Id != propietarioDb.Id) return BadRequest();

				if (
					//long.IsNullOrEmpty(propietario.Dni) ||
					string.IsNullOrEmpty(propietario.Nombre) ||
					string.IsNullOrEmpty(propietario.Apellido) ||
					string.IsNullOrEmpty(propietario.Email) ||
					string.IsNullOrEmpty(propietario.Telefono)
				)
				{
					return BadRequest("Ningun campo puede ser vacio");
				}

				propietarioDb.Dni = propietario.Dni;
				propietarioDb.Nombre = propietario.Nombre;
				propietarioDb.Apellido = propietario.Apellido;
				propietarioDb.Email = propietario.Email;
				propietarioDb.Telefono = propietario.Telefono;

				contexto.Propietarios.Update(propietarioDb);
				contexto.SaveChanges();

				return Ok(propietario);
			}
			catch (Exception e)
			{
				return BadRequest(e.Message);
			}
		}

	[HttpPut("EditarClave")]
	public async Task<IActionResult> CambiarClave([FromForm] string actual, [FromForm] string nueva)
	{
		try
		{
			string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    	password: actual,
                		salt: System.Text.Encoding.ASCII.GetBytes(configuracion["Salt"]!),
                		prf: KeyDerivationPrf.HMACSHA1,
                		iterationCount: 1000,
                		numBytesRequested: 256 / 8
			));
			Propietario p = contexto.Propietarios.AsNoTracking().Where(x => x.Email == User.Identity!.Name).First();
			if(p.Password!= hash){
				return BadRequest("Error: clave actual ingresada incorrecta");
			}
			string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    	password: nueva,
                		salt: System.Text.Encoding.ASCII.GetBytes(configuracion["Salt"]!),
                		prf: KeyDerivationPrf.HMACSHA1,
                		iterationCount: 1000,
                		numBytesRequested: 256 / 8
			));
			if(p.Password == hashed){
				return BadRequest("Error: la clave nueva no puede ser igual a la actual");
			}
            p.Password = hashed;
			contexto.Propietarios.Update(p);
			await contexto.SaveChangesAsync();
			var key = new SymmetricSecurityKey(
							System.Text.Encoding.ASCII.GetBytes(configuracion["TokenAuthentication:SecretKey"]!));
			var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.Name, p.Email),
				new Claim("FullName", p.Nombre + " " + p.Apellido),
			};

			var token = new JwtSecurityToken(
				issuer: configuracion["TokenAuthentication:Issuer"],
				audience: configuracion["TokenAuthentication:Audience"],
				claims: claims,
				expires: DateTime.Now.AddMinutes(60),
				signingCredentials: credenciales
			);
			return Ok(new JwtSecurityTokenHandler().WriteToken(token));
		}
		catch (Exception ex)
		{
			return BadRequest(ex.Message);
		}
	}

	
	private string GetLocalIpAddress()
		{
			string? localIp = null;
			var host = Dns.GetHostEntry(Dns.GetHostName());
			foreach (var ip in host.AddressList)
			{
				if (ip.AddressFamily == AddressFamily.InterNetwork)
				{
					localIp = ip.ToString();
					break;
				}
			}
			return localIp!;
		}

		[HttpPost("olvidecontraseña")]
		[AllowAnonymous]
		public async Task<IActionResult> EnviarEmail([FromForm] string email)
		{
			try
			{
				var propietario = await contexto.Propietarios.FirstOrDefaultAsync(x => x.Email == email);
				if (propietario == null)
				{
					return NotFound("No se encontró ningún usuario con esta dirección de correo electrónico.");
				}
				var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuracion["TokenAuthentication:SecretKey"]!));
				var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
				var claims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, propietario.Email),
					new Claim("FullName", $"{propietario.Nombre} {propietario.Apellido}"),
					new Claim(ClaimTypes.Role, "Usuario"),
				};
				var token = new JwtSecurityToken(
					issuer: configuracion["TokenAuthentication:Issuer"],
					audience: configuracion["TokenAuthentication:Audience"],
					claims: claims,
					expires: DateTime.Now.AddMinutes(5),
					signingCredentials: credenciales
				);
				var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
				var dominio = HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString();
				var resetLink = Url.Action("CambiarPassword", "Propietarios");
				var rutaCompleta = Request.Scheme + "://" + GetLocalIpAddress() + ":" + Request.Host.Port + resetLink;
				var message = new MimeMessage();
				message.To.Add(new MailboxAddress(propietario.Nombre, propietario.Email));
				message.From.Add(new MailboxAddress("Sistema", configuracion["SMTPUser"]));
				message.Subject = "Restablecimiento de Contraseña";
				message.Body = new TextPart("html")
				{
					Text = $@"<h1>Hola {propietario.Nombre},</h1>
						   <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.
							<p>Por favor, haz clic en el siguiente enlace para crear una nueva contraseña:</p>
						   <a href='{rutaCompleta}?access_token={tokenString}'>{rutaCompleta}?access_token={tokenString}</a>"
				};
				using var client = new SmtpClient();
				client.ServerCertificateValidationCallback = (s, c, h, e) => true;
				await client.ConnectAsync("sandbox.smtp.mailtrap.io", 587, MailKit.Security.SecureSocketOptions.StartTls);
				await client.AuthenticateAsync(configuracion["SMTPUser"], configuracion["SMTPPass"]);
				await client.SendAsync(message);
				await client.DisconnectAsync(true);
				return Ok("Se ha enviado el enlace de restablecimiento de contraseña correctamente.");
			}
			catch (Exception ex)
			{
				return BadRequest($"Error: {ex.Message}");
			}
		}

		[HttpGet("cambiarpassword")]
		public async Task<IActionResult> CambiarPassword()
		{
			try
			{
				var tokenHandler = new JwtSecurityTokenHandler();
				var key = Encoding.ASCII.GetBytes(configuracion["TokenAuthentication:SecretKey"]!);
				var symmetricKey = new SymmetricSecurityKey(key);
				Random rand = new Random(Environment.TickCount);
				string randomChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
				string nuevaClave = "";
				for (int i = 0; i < 8; i++)
				{
					nuevaClave += randomChars[rand.Next(0, randomChars.Length)];
				}
				string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
					password: nuevaClave,
					salt: Encoding.ASCII.GetBytes(configuracion["Salt"]!),
					prf: KeyDerivationPrf.HMACSHA1,
					iterationCount: 1000,
					numBytesRequested: 256 / 8));
				var p = await contexto.Propietarios.FirstOrDefaultAsync(x => x.Email == User.Identity!.Name);
				if (p == null)
				{
					return BadRequest("Nombre de usuario incorrecto");
				}
				else
				{
					p.Password = hashed;
					contexto.Propietarios.Update(p);
					await contexto.SaveChangesAsync();
					var message = new MimeMessage();
					message.To.Add(new MailboxAddress(p.Nombre, p.Email));
					message.From.Add(new MailboxAddress("Sistema", configuracion["SMTPUser"]));
					message.Subject = "Restablecimiento de Contraseña";
					message.Body = new TextPart("html")
					{
						Text = $"<h1>Hola {p.Nombre},</h1>" +
							   $"<p>Has cambiado tu contraseña de forma correcta. " +
							   $"Tu nueva contraseña es la siguiente: {nuevaClave}</p>"
					};
					using var client = new SmtpClient();
					client.ServerCertificateValidationCallback = (s, c, h, e) => true;
					await client.ConnectAsync("sandbox.smtp.mailtrap.io", 587, MailKit.Security.SecureSocketOptions.StartTls);
					await client.AuthenticateAsync(configuracion["SMTPUser"], configuracion["SMTPPass"]);
					await client.SendAsync(message);
					await client.DisconnectAsync(true);

					return Ok("Se ha restablecido la contraseña correctamente.");
				}
			}
			catch (Exception ex)
			{
				return BadRequest(ex.Message);
			}
		}
	
	}
}