using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Pago
    {
        [Key]
		public int Id { get; set; }
		public int Numero { get; set; } = 0;
		[DataType(DataType.Date)]
		public DateTime Fecha { get; set; } = DateTime.Today;
		[DataType(DataType.Currency)]
		[Column(TypeName = "decimal(10, 2)")]
		public decimal Importe { get; set; } = 0;
		[Display(Name = "Contrato")]
		public int ContratoId { get; set; }
		[ForeignKey(nameof(ContratoId))]
		public Contrato? Contrato { get; set; }

    }
