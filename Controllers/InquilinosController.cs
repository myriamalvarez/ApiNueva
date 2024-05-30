using System.Security.Claims;
using ApiNueva.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ApiNueva.Controllers
{
    [Route("[Controller]")]
	[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
	[ApiController]
	public class InquilinosController : ControllerBase
	{
		private readonly DataContext contexto;
		private readonly IConfiguration configuracion;
		public InquilinosController(DataContext context, IConfiguration config)
		{
			contexto = context;
			configuracion = config;
		}

	 // GET: Inquilinos/Obtener/{inmueble_id}
		[HttpGet("Obtener/{inmueble_id}")]
		[Authorize]
		public IActionResult GetPorInmueble(int inmueble_id)
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);

				var usuario = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (usuario == null) return NotFound();

				var inmueble = contexto.Inmuebles.Find(inmueble_id);

				if (inmueble == null) return NotFound();
				if (usuario.Id != inmueble.PropietarioId) return Unauthorized(); // Verificar que el inmueble sea del usuario

				var inquilino = contexto.Contratos
					.Include(c => c.Inquilino)
					.Where(c => c.InmuebleId == inmueble_id)
					.Select(c => c.Inquilino)
					.FirstOrDefault();

				if (inquilino == null) return NotFound();

				return Ok(inquilino);
			}
			catch (Exception e)
			{
				return BadRequest(e.Message);
			}
		}
}

		
}