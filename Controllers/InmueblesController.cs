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
	public class InmueblesController : ControllerBase
	{
		private readonly DataContext contexto;
		private readonly IConfiguration configuracion;
		private readonly IWebHostEnvironment environment;

		public InmueblesController(DataContext context, IConfiguration config, IWebHostEnvironment env)
		{
			contexto = context;
			configuracion = config;
			environment = env;
		}

		// GET: Inmuebles/
		[HttpGet("Todos")]
		[Authorize]
		public IActionResult GetTodos()
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);
				var usuario = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (usuario == null) return NotFound();

				return Ok(contexto.Inmuebles.Include(i => i.Propietario).Where(e => e.Propietario!.Id == usuario.Id));
			}
			catch (Exception e)
			{
				return BadRequest(e.Message);
			}
		}

		// GET: Inmuebles/
		[HttpGet("Obtener/{inmueble_id}")]
		[Authorize]
		public IActionResult GetInmueble(int inmueble_id)
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);
				var usuario = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (usuario == null) return NotFound();

				return Ok(contexto.Inmuebles.Find(inmueble_id));
			}
			catch (Exception e)
			{
				return BadRequest(e.Message);
			}
		}
		
		 [HttpPut("Editar/{id}")]
    public async Task<IActionResult> PutInmueble(Inmueble inmueble)
    {
        try
        {
            if (ModelState.IsValid && contexto.Inmuebles.AsNoTracking().Include(e => e.Propietario).FirstOrDefault(e => e.Id == inmueble.Id && e.Propietario!.Email == User.Identity!.Name) != null)
            {
               var propiedad = await contexto.Inmuebles.FindAsync(inmueble.Id);
               propiedad!.Estado= inmueble.Estado;
                contexto.Inmuebles.Update(propiedad);
                await contexto.SaveChangesAsync();
                return Ok(inmueble);
            }
            return BadRequest();
        }
        catch (Exception ex)
        {
            return BadRequest(ex);
        }
    }
		

		// GET: Inmuebles/Alquilados
		[HttpGet("Alquilados")]
		[Authorize]
		public IActionResult GetAlquilados()
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);
				var usuario = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (usuario == null)
					return NotFound();

				var currentDate = DateTime.Today;

				var inmuebles = contexto.Contratos
					.Include(c => c.Inmueble)
					.Where(c => c.Inmueble!.PropietarioId == usuario.Id)
					.Where(c => c.Estado == 1 && c.Desde <= currentDate && c.Hasta >= currentDate)
					.Select(c => c.Inmueble)
					.ToList();

				return Ok(inmuebles);
			}
			catch (Exception e)
			{
				return BadRequest(e.Message);
			}
		}

		// POST: Inmuebles/Crear
		[HttpPost("Crear")]
		[Authorize]
		public async Task<IActionResult> PostCrear([FromForm] Inmueble inmueble)
		{
			try
			{
				int.TryParse(User.FindFirstValue("Id"), out int userId);
				var usuario = User.Identity != null
					? contexto.Propietarios.Find(userId)
					: null;

				if (usuario == null)
					return NotFound();

				inmueble.PropietarioId = usuario.Id;
				inmueble.Propietario = usuario;
				inmueble.Estado = false;
				contexto.Inmuebles.Add(inmueble);

				contexto.SaveChanges();
				if (inmueble.ImagenFileName != null && inmueble.Id > 0)
				{
					string wwwPath = environment.WebRootPath;
					string path = Path.Combine(wwwPath, "uploads");
					if (!Directory.Exists(path))
					{
						Directory.CreateDirectory(path);
					}

					string fileName = "casa_" + inmueble.Id + Path.GetExtension(inmueble.ImagenFileName.FileName);
					string pathCompleto = Path.Combine(path, fileName);
					inmueble.Imagen = Path.Combine("/uploads", fileName);
					using (FileStream stream = new FileStream(pathCompleto, FileMode.Create))
					{
						inmueble.ImagenFileName.CopyTo(stream);
					}
					contexto.Update(inmueble);
					contexto.SaveChanges();
				}

				return Ok(inmueble);
			}
			catch (Exception ex)
			{
				return BadRequest(ex.Message);
			}
		}
	}
}
