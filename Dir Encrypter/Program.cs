// Importa funcionalidades básicas
using System;
// Importa manejo de archivos y directorios
using System.IO;
// Importa para operaciones criptográficas
using System.Security.Cryptography;
// Importa manipulación de texto
using System.Text;
// Importa para diálogos gráficos (explorador)
using System.Windows.Forms;        

class Program
{
    // Método principal con atributo STA para uso de diálogos Windows Forms
    [STAThread]
    static void Main()
    {
        // Muestra la pantalla inicial con instrucciones para el usuario
        MostrarIntro();

        // Solicita al usuario que elija entre cifrar o descifrar
        Console.Write("¿Cifrar (C) o Descifrar (D)? ");
        string modo = Console.ReadLine().ToUpper();

        // Variable para almacenar la ruta seleccionada de carpeta
        string carpeta = null;

        // Verifica si la opción elegida es válida
        if (modo == "C" || modo == "D")
        {
            // Abre un diálogo para que el usuario seleccione una carpeta
            carpeta = SeleccionarCarpeta();

            // Si no selecciona ninguna carpeta, muestra mensaje y termina
            if (string.IsNullOrEmpty(carpeta))
            {
                Console.WriteLine("No se seleccionó ninguna carpeta. Saliendo...");
                Console.WriteLine("Pulsa ENTER para salir...");
                Console.ReadLine();
                return;
            }
        }
        else
        {
            // Si la opción no es válida, informa y termina
            Console.WriteLine("Opción no válida. Saliendo...");
            Console.WriteLine("Pulsa ENTER para salir...");
            Console.ReadLine();
            return;
        }

        // Ejecuta cifrado o descifrado según la elección del usuario
        if (modo == "C")
            CifrarCarpeta(carpeta);
        else
            DescifrarCarpeta(carpeta);

        // Pausa final para que usuario lea los mensajes antes de cerrar
        Console.WriteLine("Pulsa ENTER para salir...");
        Console.ReadLine();
    }

    // Muestra introducción e instrucciones en consola
    static void MostrarIntro()
    {
        // Limpia pantalla
        Console.Clear(); 

        // Muestra título y datos del programa
        Console.WriteLine("======================================");
        Console.WriteLine("   Folder Encryption App");
        Console.WriteLine($"   Fecha: {DateTime.Now:yyyy-MM-dd}");
        Console.WriteLine("   Autor: Juan A. Ripoll");
        Console.WriteLine("======================================");

        // Cambia color para destacar instrucciones
        var colorOriginal = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.DarkYellow;

        // Muestra instrucciones básicas para el usuario
        Console.WriteLine("Instrucciones:");
        Console.WriteLine(" - Selecciona 'C' para cifrar los archivos de una carpeta.");
        Console.WriteLine(" - Selecciona 'D' para descifrar archivos '.enc' en una carpeta.");
        Console.WriteLine("Luego se abrirá un diálogo para seleccionar la carpeta.");
        Console.WriteLine();

        // Restaura color original
        Console.ForegroundColor = colorOriginal;
    }

    // Abre diálogo gráfico para seleccionar carpeta y devuelve su ruta
    static string SeleccionarCarpeta()
    {
        // Crea diálogo de carpeta
        using (var dialogo = new FolderBrowserDialog())
        {
            // Mensaje para usuario
            dialogo.Description = "Selecciona una carpeta";
            // Devuelve ruta si se selecciona, sino null
            return dialogo.ShowDialog() == DialogResult.OK ? dialogo.SelectedPath : null;
        }
    }

    // Cifra todos los archivos de la carpeta dada
    static void CifrarCarpeta(string ruta)
    {
        // Obtiene todos los archivos de la carpeta
        var archivos = Directory.GetFiles(ruta);

        // Pregunta si usuario quiere introducir contraseña manual
        Console.Write("¿Quieres introducir contraseña manual? (S/N): ");
        string respuesta = Console.ReadLine().ToUpper();

        // Variable para almacenar la contraseña usada para cifrar
        string password;

        if (respuesta == "S")
        {
            // Solicita la contraseña manual
            Console.Write("Introduce la contraseña para cifrar: ");
            password = Console.ReadLine();

            // Valida que no esté vacía
            while (string.IsNullOrEmpty(password))
            {
                Console.Write("La contraseña no puede estar vacía. Intenta de nuevo: ");
                password = Console.ReadLine();
            }
        }
        else
        {
            // Genera contraseña segura aleatoria y la muestra
            password = GenerarPasswordSegura(16);
            Console.WriteLine($"Contraseña generada automáticamente: {password}");
        }

        // Crea instancia AES para cifrado
        using (Aes aes = Aes.Create())
        {
            // Genera sal aleatoria para derivar clave e IV
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Deriva clave e IV con PBKDF2 usando contraseña y sal
            using (var keyDerivator = new Rfc2898DeriveBytes(password, salt, 100_000))
            {
                // clave 256 bits
                aes.Key = keyDerivator.GetBytes(32);
                // IV 128 bits
                aes.IV = keyDerivator.GetBytes(16);
            }

            // Obtiene nombre de la carpeta para archivo de clave
            string nombreCarpeta = new DirectoryInfo(ruta).Name;

            // Construye contenido del archivo de clave: salt|clave|iv en Base64
            string nombreClave = $"key-dir-{nombreCarpeta}.txt";

            // Une las partes en Base64 separadas por '|'
            string contenidoClave = Convert.ToBase64String(salt) + "|" +
                                   Convert.ToBase64String(aes.Key) + "|" +
                                   Convert.ToBase64String(aes.IV);

            // Guarda archivo de clave en la carpeta seleccionada
            File.WriteAllText(Path.Combine(ruta, nombreClave), contenidoClave);

            // Recorre archivos para cifrar
            foreach (var f in archivos)
            {
                // Omite el archivo de clave para evitar cifrarlo
                if (Path.GetFileName(f).StartsWith("key-dir-")) continue;

                // Lee bytes originales
                var datos = File.ReadAllBytes(f);

                // Cifra los datos usando AES
                var cifrado = Transformar(datos, aes.Key, aes.IV, true);

                // Guarda archivo cifrado con extensión ".enc"
                File.WriteAllBytes(f + ".enc", cifrado);
            }

            // Pregunta si desea borrar archivos originales sin cifrar
            Console.Write("¿Borrar archivos originales? (S/N): ");
            if (Console.ReadLine().ToUpper() == "S")
            {
                foreach (var f in archivos)
                {
                    if (!Path.GetFileName(f).StartsWith("key-dir-")) File.Delete(f);
                }
            }
        }

        // Mensaje de finalización del cifrado
        Console.WriteLine("Cifrado completado.");
    }

    // Descifra archivos ".enc" usando archivo de clave seleccionado por diálogo gráfico
    static void DescifrarCarpeta(string ruta)
    {
        // Crear y configurar diálogo para seleccionar archivo de clave
        using (var openFileDialog = new OpenFileDialog())
        {
            // Carpeta inicial para buscar archivo
            openFileDialog.InitialDirectory = ruta;
            // Filtro solo .txt
            openFileDialog.Filter = "Archivos de clave (*.txt)|*.txt|Todos los archivos (*.*)|*.*";
            openFileDialog.Title = "Selecciona el archivo de clave";

            // Mostrar diálogo y verificar si usuario seleccionó archivo
            if (openFileDialog.ShowDialog() != DialogResult.OK)
            {
                Console.WriteLine("No se seleccionó ningún archivo de clave. Saliendo...");
                return;
            }

            // Obtener ruta completa del archivo seleccionado
            string rutaClave = openFileDialog.FileName;

            // Leer contenido del archivo clave (salt|clave|iv en Base64)
            string contenidoClave = File.ReadAllText(rutaClave);
            var partes = contenidoClave.Split('|');

            // Validar formato correcto de archivo clave
            if (partes.Length != 3)
            {
                Console.WriteLine("Formato del archivo de clave inválido.");
                return;
            }

            // Convertir sal de Base64 a bytes
            byte[] salt = Convert.FromBase64String(partes[0]);

            // Solicitar contraseña para derivar clave e IV
            Console.Write("Introduce la contraseña para descifrar: ");
            string password = Console.ReadLine();

            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Contraseña vacía.");
                return;
            }

            byte[] clave;
            byte[] iv;

            try
            {
                // Derivar clave e IV con PBKDF2
                using (var keyDerivator = new Rfc2898DeriveBytes(password, salt, 100_000))
                {
                    clave = keyDerivator.GetBytes(32);
                    iv = keyDerivator.GetBytes(16);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error derivando clave e IV: " + ex.Message);
                return;
            }

            // Buscar todos los archivos cifrados con extensión ".enc"
            foreach (var f in Directory.GetFiles(ruta, "*.enc"))
            {
                try
                {
                    // Leer bytes cifrados
                    var cifrado = File.ReadAllBytes(f);

                    // Descifrar usando clave e IV derivados
                    var claro = Transformar(cifrado, clave, iv, false);

                    // Nombre original quitando extensión ".enc"
                    string original = f.Substring(0, f.Length - 4);

                    // Guardar archivo descifrado
                    File.WriteAllBytes(original, claro);

                    // Eliminar archivo cifrado
                    File.Delete(f);
                }
                catch (CryptographicException)
                {
                    // Si la clave o contraseña son incorrectas
                    Console.WriteLine($"Error al descifrar {Path.GetFileName(f)}: Contraseña incorrecta o archivo corrupto.");
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error inesperado al descifrar {Path.GetFileName(f)}: {ex.Message}");
                    return;
                }
            }

            // Mensaje de finalización del descifrado
            Console.WriteLine("Descifrado completado.");
        }
    }

    // Método para cifrar o descifrar bytes con AES
    static byte[] Transformar(byte[] datos, byte[] clave, byte[] iv, bool cifrar)
    {
        // Crear AES
        using (Aes aes = Aes.Create())
        // Crear cifrador o descifrador
        using (var transformador = cifrar ? aes.CreateEncryptor(clave, iv) : aes.CreateDecryptor(clave, iv))
        // Memoria temporal
        using (var ms = new MemoryStream())
        // Flujo de cifrado
        using (var cs = new CryptoStream(ms, transformador, CryptoStreamMode.Write)) 
        {
            // Escribe datos al flujo
            cs.Write(datos, 0, datos.Length);
            // Finaliza cifrado
            cs.FlushFinalBlock();
            // Devuelve resultado
            return ms.ToArray();                                         
        }
    }

    // Genera contraseña segura aleatoria de longitud dada (por ejemplo 16)
    static string GenerarPasswordSegura(int longitud)
    {
        const string caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
        var bytes = new byte[longitud];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        var resultado = new StringBuilder(longitud);
        foreach (byte b in bytes)
        {
            resultado.Append(caracteres[b % caracteres.Length]);
        }
        return resultado.ToString();
    }
}
