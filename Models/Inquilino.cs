using System.ComponentModel.DataAnnotations;

public class Inquilino
    {
       [Key]
		public int Id { get; set; }
		public string Nombre { get; set; } = "";
		public string Apellido { get; set; } = "";
		public long Dni { get; set; }
		public string? Telefono { get; set; }
		public string? Email { get; set; }
		public string? nombreGarante { get; set; }
		public string? telefonoGarante { get; set; }
		public int Estado { get; set; } = 1;
    }