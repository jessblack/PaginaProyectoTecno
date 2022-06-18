using System;
using System.Text;
using ProyectoMVC.Models;
using ProyectoMVC.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
namespace ProyectoMVC.Services
{
	public class TokenService : ITokenService
	{
		private readonly SymmetricSecurityKey _ssKey;
		public TokenManagement tokenDatos;
		public TokenService(IConfiguration config)
		{
            tokenDatos = config.GetSection("tokenManagement").Get<TokenManagement>();
			_ssKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenDatos.Secret));
		}
		public string CreateToken(string Texto)
		{
			var tokenRes="";
		try
		{
			var claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.NameId, Texto)
			};
			var credenciales = new SigningCredentials(_ssKey, SecurityAlgorithms.HmacSha256Signature);
/*			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Expires = System.DateTime.Now.AddMinutes(30),
				SigningCredentials = credenciales
			};
			var tokenHandler = new JwtSecurityTokenHandler();
			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);*/
			var jwtToken = new JwtSecurityToken(tokenDatos.Issuer, tokenDatos.Audience, claims, expires: System.DateTime.Now.AddMinutes(tokenDatos.AccessExpiration), signingCredentials: credenciales);
            tokenRes = new JwtSecurityTokenHandler().WriteToken(jwtToken);
		}
        catch (Exception ex)
        {
        	tokenRes ="No es posible crear";
        }
             return tokenRes;
		}
		public string CreateToken2(string Texto)
		{
			var tokenRes="";
			try
			{
				var claims = new List<Claim>
				{
					new Claim(JwtRegisteredClaimNames.NameId, Texto)
				};
				var credenciales = new SigningCredentials(_ssKey, SecurityAlgorithms.HmacSha256Signature);
				var jwtToken = new JwtSecurityToken(tokenDatos.Issuer, tokenDatos.Audience, claims, expires: System.DateTime.Now.AddMinutes(144000), signingCredentials: credenciales);
	            tokenRes = new JwtSecurityTokenHandler().WriteToken(jwtToken);
			}
	        catch (Exception ex)
	        {
	        	tokenRes ="No es posible crear";
	        }
             return tokenRes;
		}



		public string DesencriptarToken(string Texto)
		{
		string tokenValor="";
        int VerTokenUsuario = 0;
		try
		{
			double expira=0;
			var stream = Texto;  
			var handler = new JwtSecurityTokenHandler();
			var jsonToken = handler.ReadToken(stream);
			var tokenS = jsonToken as JwtSecurityToken;
			foreach (var token in tokenS.Claims){
				if(token.Type=="nameid"){
					tokenValor=token.Value.ToString();
				}
				if(token.Type=="exp"){
					expira=Int32.Parse(token.Value);
				}
			}
			TimeSpan span= DateTime.UtcNow.Subtract(new DateTime(1970,1,1,0,0,0));
			if(span.TotalSeconds >= expira){
				tokenValor = "Token expirado";
			}
            conexion conn= new conexion();

            using (SqlConnection connection = new SqlConnection(conn.Conectar()))
            {
                try
                {
                    connection.Open();
                    SqlCommand cmd = new SqlCommand();  
                    cmd.CommandText = "select * from dbo.tbl_Usuario where token=@Token";
					SqlParameter param  = new SqlParameter();
					param.ParameterName = "@Token";
					param.Value = Texto;
					cmd.Parameters.Add(param);
                    cmd.CommandType = CommandType.Text;
                    cmd.Connection = connection; 
                        using (var reader = cmd.ExecuteReader()){
                            int verificador = 0;
                            while (reader.Read())
                            {
                                VerTokenUsuario=1;
                            }
                        }
                }
                catch (Exception exception)
                {
                    tokenValor ="Token invalido";
                }
            }

		}
        catch (Exception ex)
        {
        	tokenValor ="Token invalido";
        }
        if(VerTokenUsuario==0){
        	tokenValor ="Token invalido";
        }
			return tokenValor;
		}
		public string DesencriptarToken2(string Texto)
		{
		string tokenValor="";
        int VerTokenUsuario = 0;
		try
		{
			double expira=0;
			var stream = Texto;  
			var handler = new JwtSecurityTokenHandler();
			var jsonToken = handler.ReadToken(stream);
			var tokenS = jsonToken as JwtSecurityToken;
			foreach (var token in tokenS.Claims){
				if(token.Type=="nameid"){
					tokenValor=token.Value.ToString();
				}
				if(token.Type=="exp"){
					expira=Int32.Parse(token.Value);
				}
			}
			TimeSpan span= DateTime.UtcNow.Subtract(new DateTime(1970,1,1,0,0,0));
			if(span.TotalSeconds >= expira){
				tokenValor = "Token expirado";
			}

		}
        catch (Exception ex)
        {
        	tokenValor ="Token invalido";
        }
			return tokenValor;
		}


	}
}