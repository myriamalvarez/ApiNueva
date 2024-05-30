using System.ComponentModel.DataAnnotations;

public class Propietario
    {
        [Display(Name = "Código")]
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [MaxLength(50, ErrorMessage = "El campo {0} debe tener máximo {1} caractéres.")]
        public string Nombre { get; set; } = "";

        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [MaxLength(50, ErrorMessage = "El campo {0} debe tener máximo {1} caractéres.")]
        public string Apellido { get; set; } = "";

        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        //[MaxLength(20, ErrorMessage = "El campo {0} debe tener máximo {1} caractéres.")]
        public long Dni { get; set; } 

        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [Display(Name = "Teléfono")]
        //[MaxLength(20, ErrorMessage = "El campo {0} debe tener máximo {1} caractéres.")]
        public string Telefono { get; set; } = "";

        [Required(ErrorMessage = "El campo {0} es obligatorio")]
        [DataType(DataType.EmailAddress)]
        //[MaxLength(50, ErrorMessage = "El campo {0} debe tener máximo {1} caractéres.")]
        public string Email { get; set; } = "";

        [Required, DataType(DataType.Password)]
        public string Password { get; set; } = "";

        public string Avatar { get; set; } = "";

        public override string ToString() => $"{Nombre} {Apellido}";
        public Propietario() { }
        public Propietario(Propietario propietario)
		{
			Id = propietario.Id;
			Nombre = propietario.Nombre;
			Apellido = propietario.Apellido;
			Dni = propietario.Dni;
			Telefono = propietario.Telefono;
			Email = propietario.Email;
			Password = propietario.Password;
			
		}
    }