namespace ProyectoMVC.Services.Interfaces
{
	public interface ITokenService
	{
		string CreateToken(string Texto);
		string CreateToken2(string Texto);
		string DesencriptarToken(string Texto);
		string DesencriptarToken2(string Texto);
	}
}