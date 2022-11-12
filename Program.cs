using System.Net;
using System.Text;
using System.Security.Cryptography;

using MailKit.Net.Smtp;
using MailKit;
using MimeKit;

using OtpNet;
using BC = BCrypt.Net.BCrypt;
using MySql.Data.MySqlClient;

enum OnError {
    NOTHING = '0',
    EXIT    = '1',
    RESTART = '2',
    RETURN  = '3',
};

static class ERRS {
    public static string InvalidUsername() {
	return (char)OnError.EXIT + "Invalid username";
    }

    public static string InvalidMail() {
	return (char)OnError.EXIT + "Invalid mail";
    }

    public static string InvalidSession() {
	return (char)OnError.EXIT + "Invalid session";
    }

    public static string InvalidToken() {
	return (char)OnError.RETURN + "Invalid token";
    }

    public static string ExpiredSession() {
	return (char)OnError.RESTART + "Session has expired";
    }

    public static string UserAlreadyExists() {
	return (char)OnError.RESTART + "User already exists";
    }

    public static string UserDoesntExist() {
	return (char)OnError.RESTART + "User does not exist";
    }

    public static string MailAlreadyExists() {
	return (char)OnError.RESTART + "Mail already registered";
    }

    public static string AuthStepSkip() {
	return (char)OnError.EXIT + "Authentication step skipped";
    }

    public static string TooManyAttempts() {
	return (char)OnError.EXIT + "Too many failed attempts";
    }
}

class TempUser {
    public DateTime start;
    public string token;
    public string mail;
    public long ip;
    public int remaining;

    public Totp totp;
    public string autoAuth;
    public string totpBase32;
    
    public int authStep = 0;
    public int loginStep = 0;
    public int attempts = 0;

    public TempUser() {
	start = DateTime.UtcNow;
	token = Program.Gen128();
    }

    public bool isExpired() {
	DateTime now = DateTime.UtcNow;
	remaining = (int)now.Subtract(start).TotalSeconds;

	return remaining > 120;
    }
}

class Program {
    static HttpListenerContext context;
    static HttpListenerRequest request;
    static HttpListenerResponse response;
    static System.IO.Stream output;
    static Dictionary<string, TempUser> sessions = new Dictionary<string, TempUser>();
    static string mailPassword;
    
    static MySqlConnection sqlCon;

    public static string Gen128() {
	Aes algo = Aes.Create();
	algo.KeySize = 128;
	algo.GenerateKey();
	return Convert.ToBase64String(algo.Key);
    }

    static void send_string(string responseString){
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        output.Write(buffer);
    }

    static void send_package(string package){
        // Pretty simple sends a package by taking all the bytes of the package
        // sending the bytes with a instruction on how to divide them correctly
        byte[] file = File.ReadAllBytes("packages/" + package + ".bin");
        string json = File.ReadAllText("packages/" + package + ".json");
        
        response.AddHeader("file", json);

        output.Write(file);        
        Console.WriteLine("Sent package " + package);
    }

    static bool chkInvalidHeader(string header) {
	return header == null;
    }

    static bool chkInvalidSession(string user) {
	return !sessions.ContainsKey(user);
    }
    
    static bool chkInvalidAuthStep(string user, int step) {
	return sessions[user].authStep != step;
    }

    static bool chkExpiredSession(string user) {
	if(sessions[user].isExpired()) {
	    sessions.Remove(user);
	    return true;
	}

	return false;
    }

    static bool chkRowColExists(string col, string val) {
	var sql = $"SELECT COUNT(1) FROM clients WHERE {col}=@data";
	using var cmd = new MySqlCommand(sql, sqlCon);

	cmd.Parameters.AddWithValue("@data", val);
	cmd.Prepare();
	using MySqlDataReader rdr = cmd.ExecuteReader();
	rdr.Read();

	int exists = rdr.GetInt32(0);
	return exists == 1;
    }

    static string[] LoginData(string user) {
	string[] ret = new string[3];

	var sql = $"SELECT auth, totp, mail FROM clients WHERE name=@name";
	using var cmd = new MySqlCommand(sql, sqlCon);
	
	cmd.Parameters.AddWithValue("@name", user);
	cmd.Prepare();
	using MySqlDataReader rdr = cmd.ExecuteReader();
	rdr.Read();
	ret[0] = rdr.GetString(0);
	ret[1] = rdr.GetString(1);
	ret[2] = rdr.GetString(2);

	return ret;
    }

    static void createAccount(string user, string mail, string authHash, string totpHash) {
	var sql = "INSERT INTO clients(name, mail, auth, totp) VALUES (@name, @mail, @auth, @totp)";
	using var cmd = new MySqlCommand(sql, sqlCon);

	cmd.Parameters.AddWithValue("@name", user);
	cmd.Parameters.AddWithValue("@mail", mail);
	cmd.Parameters.AddWithValue("@auth", authHash);
	cmd.Parameters.AddWithValue("@totp", totpHash);

	cmd.Prepare();
	cmd.ExecuteNonQuery();
    }

    static void post_package(string package){
        // wip  Will allow users to post their own packages

        Stream data = request.InputStream;

        Console.WriteLine("Package created : " + package);

        string? json = request.Headers["file"];

        Stream filestream = File.Create("packages/" + package + ".bin");
        request.InputStream.CopyTo(filestream); 

        File.WriteAllText("packages/"+ package + ".json", json);

        filestream.Close();

        Console.WriteLine("Posted package " + package);
    }

    static string get_pkg(string package){
        // This does some of the raw checking to see that nothing is wrong with the 
        // Package that the user is requesting (for example the user doing something like ..
        // Which would allow them to download random files on the server)
        // Or somehow sending blankspaces or just simply a package that doesnt exist
        Console.WriteLine(request.Headers["type"]);
        Console.WriteLine("Package name : " + package);
        string full_path = Path.GetFullPath("packages/" + package);

        if(string.IsNullOrWhiteSpace(package)){ // If the client somehow sent no name or blank space as the package name
            Console.WriteLine("No package declared");
            return "No package Declared";
        }
        if(!File.Exists("packages/" + package + ".bin")){// If the client sent a package name but it doesn't exist
            Console.WriteLine("Package " + package + "  does not exist!");
            return "Package " + package + " does not exist!";
        }
        if(!full_path.StartsWith("/Users/leonj/projects/bssh-host/packages/")){ // If the user has somehow tried to access different locations
            Console.WriteLine("Cheeky?");
            return "Weird package name";
        }         
        if(request.Headers["type"] == "get-pkg"){ // If the type the client is asking for is get a package (What command they are asking off from)
            send_package(package);
            return "Package sent";
        }
        return "";
    }

    static void closeOutput(string res){
	response.ContentLength64 = res.Length;
        send_string(res);
        output.Close();
    }

    static bool pass(){
        string? pass = request.Headers["pass"];

        if(string.IsNullOrWhiteSpace(pass)){
            return false;
        }

        string[] lines = File.ReadAllLines("password.txt");  
        foreach (string line in lines){ 
            if(BC.Verify(pass, line)){
                return true;
            }
        }

        return false;
    }

    static void SendConfirmationMail() {
	/*
	try {
	    var message = new MimeMessage();
	    message.From.Add (new MailboxAddress("noreply", "noreply@basilisk.sh"));
	    message.To.Add (new MailboxAddress(user, mail));
	    message.Subject = "Authentication Token";

	    message.Body = new TextPart("html") {
		Text = "Provide this token for your account creation: <b>" + tempUser.token + "</b>",
	    };

	    using (var client = new SmtpClient()) {
		client.Connect ("smtp.porkbun.com", 587, false);

		client.Authenticate("noreply@basilisk.sh", mailPassword);

		client.Send (message);
		client.Disconnect (true);
	    }
	} catch {
	    sessions.Remove(user);
	    closeOutput(Errors.EMAIL_FAIL);
	    return;
	}
*/
    }

    static string login_0() {
	string? user;
	user = request.Headers["User"];

	if(chkInvalidHeader(user))
	    return ERRS.InvalidUsername();

	if(!chkRowColExists("name", user))
	    return ERRS.UserDoesntExist();

	string[] loginData = LoginData(user);
	string auth = loginData[0];
	string totp = loginData[1];
	string mail = loginData[2];

	long ip = request.RemoteEndPoint.Address.Address;
	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("LOG IN REQUEST \"" + user + "\" " + "(" + ip + ")");
	Console.ForegroundColor = ConsoleColor.White;

	TempUser tempUser = new TempUser();
	tempUser.token = "1234";
	tempUser.mail = mail;
	tempUser.ip = ip;

	SendConfirmationMail();

	if(sessions.ContainsKey(user)) {
	    if(request.RemoteEndPoint.Address.Address != sessions[user].ip) {
		return ERRS.UserAlreadyExists();
	    }
	    sessions[user] = tempUser;
	} else {
	    sessions.Add(user, tempUser);
	}

	sessions[user].loginStep++;
	return (char)OnError.NOTHING + "";
    }

    static string login_1() {
    }

    static string auth_0() {
	string? user, mail;
	user = request.Headers["User"];
	mail = request.Headers["Mail"];

	if(chkInvalidHeader(user))
	    return ERRS.InvalidUsername();

	if(chkInvalidHeader(mail))
	    return ERRS.InvalidMail();

	if(chkRowColExists("name", user))
	    return ERRS.UserAlreadyExists();
	
	if(chkRowColExists("mail", mail))
	    return ERRS.MailAlreadyExists();

	long ip = request.RemoteEndPoint.Address.Address;
	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("AUTHENTICATING \"" + user + "\" " + "(" + ip + ")");
	Console.ForegroundColor = ConsoleColor.White;

	TempUser tempUser = new TempUser();
	tempUser.token = "1234";
	tempUser.mail = mail;
	tempUser.ip = ip;

	if(sessions.ContainsKey(user)) {
	    if(request.RemoteEndPoint.Address.Address != sessions[user].ip) {
		return ERRS.UserAlreadyExists();
	    }
	    sessions[user] = tempUser;
	} else {
	    sessions.Add(user, tempUser);
	}

	SendConfirmationMail();

	Cookie cookie = new Cookie();
	cookie.Expires = DateTime.UtcNow.AddYears(10);
	cookie.Name = "auth";
	cookie.Value = Gen128();

	response.Cookies.Add(cookie);
	sessions[user].autoAuth = cookie.Value;
	sessions[user].authStep++;

	return (char)OnError.NOTHING + "";
    }

    static string auth_1() {
	string? user, toke;
	user = request.Headers["User"];
	toke = request.Headers["Toke"];

	if(chkInvalidHeader(user))
	    return ERRS.UserAlreadyExists();

	if(chkInvalidSession(user))
	    return ERRS.InvalidSession();

	if(chkInvalidAuthStep(user, 1))
	    return ERRS.AuthStepSkip();

	if(chkExpiredSession(user))
	    return ERRS.ExpiredSession();

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("CHECKING EMAIL TOKEN FOR \"" + user + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	if(sessions[user].token != toke) {
	    if(++sessions[user].attempts == 3) {
		sessions.Remove(user);
		Console.WriteLine("TOO MANY ATTEMPTS!");
		return ERRS.TooManyAttempts();
	    }

	    return ERRS.InvalidToken();
	}

	sessions[user].attempts = 0;
	sessions[user].authStep++;
	return (char)OnError.NOTHING + "";
    }

    static string auth_2() {
	string? user;
	user = request.Headers["User"];

	if(chkInvalidHeader(user))
	    return ERRS.InvalidUsername();

	if(chkInvalidSession(user))
	    return ERRS.InvalidSession();

	if(chkInvalidAuthStep(user, 2))
	    return ERRS.AuthStepSkip();

	if(chkExpiredSession(user))
	    return ERRS.ExpiredSession();

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("TOTP FOR \"" + user + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	var key = KeyGeneration.GenerateRandomKey(20);

	var base32String = Base32Encoding.ToString(key);
	var base32Bytes = Base32Encoding.ToBytes(base32String);

	var totp = new Totp(base32Bytes);
	var code = totp.ComputeTotp();

	sessions[user].totp = totp;
	sessions[user].totpBase32 = base32String;
	sessions[user].authStep++;

	return (char)OnError.NOTHING + "otpauth://totp/bssh?secret=" + base32String;
    }

    static string auth_3() {
	string? user, totp;
	user = request.Headers["User"];
	totp = request.Headers["Totp"];

	if(chkInvalidHeader(user))
	    return ERRS.InvalidUsername();

	if(chkInvalidHeader(totp))
	    return ERRS.InvalidToken();

	if(chkInvalidSession(user))
	    return ERRS.InvalidSession();

	if(chkInvalidAuthStep(user, 3))
	    return ERRS.AuthStepSkip();

	if(chkExpiredSession(user))
	    return ERRS.ExpiredSession();

	string totp_cmp = sessions[user].totp.ComputeTotp();
	totp = totp.Replace(" ", "");
	bool ok = totp_cmp == totp;

	Console.WriteLine("Comparing: " + totp + " | " + totp_cmp + " (" + (ok ? "CORRECT" : "INCORRECT") + ")");

	if(!ok) {
	    if(++sessions[user].attempts == 3)
		return ERRS.TooManyAttempts();

	    return ERRS.InvalidToken();
	}

	string authHash = BC.HashPassword(sessions[user].autoAuth);
	string totpHash = BC.HashPassword(sessions[user].totpBase32);

	createAccount(user, sessions[user].mail, authHash, totpHash);
	sessions.Remove(user);

	return (char)OnError.NOTHING + "";
    }

    static void listen(HttpListener listener){
        // Sets up the program to whatever user is requesting a function
        // Figures out what the user wants and sends them on their way :)
	context = listener.GetContext();
        request = context.Request;
        response = context.Response;
        output = response.OutputStream;
        
	string? type = request.Headers["Type"];
	string ret = (char)OnError.NOTHING + "Unknown type";

	switch(type) {
	    case "auth_0": ret = auth_0(); break;
	    case "auth_1": ret = auth_1(); break;
	    case "auth_2": ret = auth_2(); break;
	    case "auth_3": ret = auth_3(); break;

	    case "login_0": ret = login_0(); break;
	    case "login_1": ret = login_1(); break;

	    default: break;
	}

	closeOutput(ret);
	return;
    }

    public static void Main() {
        HttpListener listener = new HttpListener();

	string[] lines = File.ReadAllLines("secrets.txt");
	mailPassword = lines[0];

	Console.WriteLine("Connecting to SQL...");
	string cs = lines[1];
	sqlCon = new MySqlConnection(cs);
	sqlCon.Open();
	Console.WriteLine($"MySQL Version { sqlCon.ServerVersion }");

	int port = 8001;
        listener.Prefixes.Add("http://*:" + port + "/");
        listener.Start();
	
	Console.WriteLine("Listening on port " + port);

        while(true){
            listen(listener);
        }
        //listener.Close();
    }
}
