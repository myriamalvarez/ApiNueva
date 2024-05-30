using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Inmueble
{
    
    [Key]
		public int Id { get; set; }
		public string? Uso { get; set; } //Residencial, Comercial
		public string? Tipo { get; set; } //Casa, Departamento, Oficina, Local, Deposito
		public string Direccion { get; set; } = "";
		public int Ambientes { get; set; } = 1;
		public decimal Precio { get; set; } = 0;
		public Boolean Estado { get; set; } = true;
		public string? Imagen { get; set; } = "";
		[NotMapped]
		public IFormFile? ImagenFileName { get; set; }
		[ForeignKey(nameof(Propietario))]
		public int? PropietarioId { get; set; }
		public Propietario? Propietario { get; set; } = null;
}