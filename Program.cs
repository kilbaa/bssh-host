using System.Net;

using MailKit.Net.Smtp;
using MailKit;
using MimeKit;

using OtpNet;
using BC = BCrypt.Net.BCrypt;
using MySql.Data.MySqlClient;

enum Errors {
    OK,
    INVALID_HEADER,
    INVALID_TOKEN,
    USER_ALREADY_EXISTS,
    MAIL_ALREADY_EXISTS,
    SKIPPED_STEP,
    EXPIRED,
    TOO_MANY_ATTEMPS,
    EMAIL_FAIL,
};

class TempUser {
    public DateTime start;
    public string token;
    public string mail;
    public long ip;
    public int remaining;
    public Totp totp;

    public int authStep = 0;
    public int attempts = 0;

    public TempUser() {
	start = DateTime.UtcNow;

	var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	var stringChars = new char[8];
	var random = new Random();

	for (int i = 0; i < stringChars.Length; i++) {
	    stringChars[i] = chars[random.Next(chars.Length)];
	}

	token = new String(stringChars);
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


    static void send_string(string responseString){
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        output.Write(buffer);
    }

    static void send_error(Errors response){
        byte[] buffer = BitConverter.GetBytes((int)response);
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
	if(header == null) {
	    Console.WriteLine("    Invalid Header");
	    closeOutput(Errors.INVALID_HEADER);
	    return true;
	}

	return false;
    }

    static bool chkInvalidSession(string user) {
	if(!sessions.ContainsKey(user)) {
	    Console.WriteLine("    Invalid Session");
	    closeOutput(Errors.INVALID_HEADER); // TODO: INVALID_SESSION
	    return true;
	}

	return false;
    }
    
    static bool chkInvalidAuthStep(string user, int step) {
	if(sessions[user].authStep != step) {
	    Console.WriteLine("    Tried Skipping Authentication Steps");
	    closeOutput(Errors.SKIPPED_STEP);
	    return true;
	}

	return false;
    }

    static bool chkExpiredSession(string user) {
	if(sessions[user].isExpired()) {
	    Console.WriteLine("    Session Expired");
	    sessions.Remove(user);
	    closeOutput(Errors.EXPIRED);
	    return true;
	}

	return false;
    }


    static bool chkRowColExists(string col, string val, Errors ret) {
	try {
	    var sql = $"SELECT COUNT(1) FROM clients WHERE {col}=@data";
	    using var cmd = new MySqlCommand(sql, sqlCon);

	    cmd.Parameters.AddWithValue("@data", val);
	    cmd.Prepare();
	    using MySqlDataReader rdr = cmd.ExecuteReader();
	    rdr.Read();

	    int exists = rdr.GetInt32(0);
	    if(exists == 1) {
		closeOutput(ret);
		return true;
	    }
	} catch(Exception e) { 
	    Console.WriteLine(e);
	    closeOutput(ret);
	    return true;
	}

	return false;
    }

    static bool chkMailExists(string mail) {
	return chkRowColExists("mail", mail, Errors.MAIL_ALREADY_EXISTS);
    }

    static bool chkUserExists(string user) {
	return chkRowColExists("name", user, Errors.USER_ALREADY_EXISTS);
    }

    static void createAccount(string user, string mail) {
	var sql = "INSERT INTO clients(name, mail) VALUES (@name, @mail)";
	using var cmd = new MySqlCommand(sql, sqlCon);

	cmd.Parameters.AddWithValue("@name", user);
	cmd.Parameters.AddWithValue("@mail", mail);

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

    static void closeOutput(Errors status){
	response.ContentLength64 = 4;
        send_error(status);
        output.Close();
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

    static void auth_0() {
	string? user, mail;
	user = request.Headers["User"];
	mail = request.Headers["Mail"];

	if(chkInvalidHeader(user))
	    return;

	if(chkInvalidHeader(mail))
	    return;

	if(chkUserExists(user))
	    return;
	
	if(chkMailExists(mail))
	    return;

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
		closeOutput(Errors.USER_ALREADY_EXISTS);
		return;
	    }
	    sessions[user] = tempUser;
	} else {
	    sessions.Add(user, tempUser);
	}

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
	sessions[user].authStep++;
	closeOutput(Errors.OK);
    }

    static void auth_1() {
	string? user, toke;
	user = request.Headers["User"];
	toke = request.Headers["Toke"];

	if(chkInvalidHeader(user))
	    return;

	if(chkInvalidSession(user))
	    return;

	if(chkInvalidAuthStep(user, 1))
	    return;

	if(chkExpiredSession(user))
	    return;

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("CHECKING EMAIL TOKEN FOR \"" + user + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	if(sessions[user].token != toke) {
	    if(++sessions[user].attempts == 3) {
		sessions.Remove(user);
		Console.WriteLine("TOO MANY ATTEMPTS!");
		closeOutput(Errors.TOO_MANY_ATTEMPS);
		return;
	    }

	    closeOutput(Errors.INVALID_TOKEN);
	    return;
	}

	sessions[user].attempts = 0;
	sessions[user].authStep++;
	closeOutput(Errors.OK);
    }

    static void auth_2() {
	string? user;
	user = request.Headers["User"];

	if(chkInvalidHeader(user))
	    return;

	if(chkInvalidSession(user))
	    return;

	if(chkInvalidAuthStep(user, 2))
	    return;

	if(chkExpiredSession(user))
	    return;

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("TOTP FOR \"" + user + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	var key = KeyGeneration.GenerateRandomKey(20);

	var base32String = Base32Encoding.ToString(key);
	var base32Bytes = Base32Encoding.ToBytes(base32String);

	var totp = new Totp(base32Bytes);
	var code = totp.ComputeTotp();

	sessions[user].totp = totp;
	sessions[user].authStep++;

	closeOutput("\0\0\0\0" + "otpauth://totp/bssh?secret=" + base32String);
    }

    static void auth_3() {
	string? user, totp;
	user = request.Headers["User"];
	totp = request.Headers["Totp"];

	if(chkInvalidHeader(user))
	    return;

	if(chkInvalidHeader(totp))
	    return;

	if(chkInvalidSession(user))
	    return;

	if(chkInvalidAuthStep(user, 3))
	    return;

	if(chkExpiredSession(user))
	    return;

	string totp_cmp = sessions[user].totp.ComputeTotp();
	totp = totp.Replace(" ", "");
	bool ok = totp_cmp == totp;

	Console.WriteLine("Comparing: " + totp + " | " + totp_cmp + " (" + (ok ? "CORRECT" : "INCORRECT") + ")");

	if(!ok) {
	    if(++sessions[user].attempts == 3) {
		closeOutput(Errors.TOO_MANY_ATTEMPS);
		return;
	    }
	    closeOutput(Errors.INVALID_TOKEN);
	    return;
	}

	createAccount(user, sessions[user].mail);
	sessions.Remove(user);
	closeOutput(Errors.OK);
    }

    static void listen(HttpListener listener){
        // Sets up the program to whatever user is requesting a function
        // Figures out what the user wants and sends them on their way :)
	context = listener.GetContext();
        request = context.Request;
        response = context.Response;
        output = response.OutputStream;
        
	string? type = request.Headers["Type"];

	switch(type) {
	    case "auth_0": auth_0(); break;
	    case "auth_1": auth_1(); break;
	    case "auth_2": auth_2(); break;
	    case "auth_3": auth_3(); break;

	    default: break;
	}
        
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
