using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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

enum FriendType : byte {
    REQUEST,
    FRIENDS,
};

public static class ERRS {
    public static string OK                   = (char)OnError.NOTHING + "";
    public static string invalidMail          = (char)OnError.EXIT    + "Invalid mail";
    public static string invalidSession       = (char)OnError.EXIT    + "Invalid session";
    public static string invalidUsername      = (char)OnError.EXIT    + "Invalid username";
    public static string invalidToken         = (char)OnError.RETURN  + "Invalid Token";
    public static string expiredSession       = (char)OnError.RESTART + "Session expired";
    public static string userAlreadyExists    = (char)OnError.RESTART + "User already exists";
    public static string userDoesntExist      = (char)OnError.RESTART + "User does not exist";
    public static string mailAlreadyExists    = (char)OnError.RESTART + "Mail already registered";
    public static string notAlphaNumerical    = (char)OnError.RESTART + "Name can only contain alphanumerical letters";
    public static string notLoggedIn          = (char)OnError.EXIT    + "You need to be logged in to perform this action";
    public static string authStepSkip         = (char)OnError.EXIT    + "Authentication step skipped";
    public static string friendReqAlreadySent = (char)OnError.EXIT    + "Friend request already sent";
    public static string tooManyAttempts      = (char)OnError.EXIT    + "Too many failed attempts";
    public static string userNotFound         = (char)OnError.EXIT    + "User was not found";
    public static string couldNotSendMail     = (char)OnError.EXIT    + "Could not send mail";
}

class TempUser {
    public DateTime start;
    public string token;
    public string mail;
    public long ip;
    public int remaining;

    public Totp totp;
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
    
    static readonly Regex alphanumRegex = new Regex("^[a-zA-Z0-9]*$");

    static string mailPassword;
    static byte[] secret;

    static MySqlConnection sqlCon;

    public static string Gen128() {
	Aes algo = Aes.Create();
	algo.KeySize = 128;
	algo.GenerateKey();
	return Convert.ToBase64String(algo.Key);
    }

    static void send_string(string responseString){
	try {
	    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
	    output.Write(buffer);
	} catch { Console.WriteLine("Failed to send response"); }
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
    
    static bool chkInvalidAuthStep(int cmp, int step) {
	return cmp != step;
    }

    static bool chkExpiredSession(string user) {
	if(sessions[user].isExpired()) {
	    sessions.Remove(user);
	    return true;
	}

	return false;
    }

    static bool chkIsNotAlphaNum(string str) {
	return !alphanumRegex.IsMatch(str);
    }

    static bool chkRowColExists(string col, string val) {
	var sql = $"SELECT COUNT(1) FROM clients WHERE {col}=@data";
	long exists = 0;
	try {
	    using var cmd = new MySqlCommand(sql, sqlCon);
	    cmd.Parameters.AddWithValue("@data", val);
	    exists = (long)cmd.ExecuteScalar();
	} catch(Exception e) { Console.WriteLine(e); }

	return exists == 1;
    }

    static bool chkLoginHashExists(int id, int ip) {
	var sql = $"SELECT COUNT(1) FROM auths WHERE id=@id AND ip=@ip";
	long exists = 0;
	try {
	    using var cmd = new MySqlCommand(sql, sqlCon);
	    cmd.Parameters.AddWithValue("@id", id);
	    cmd.Parameters.AddWithValue("@ip", ip);
	    exists = (long)cmd.ExecuteScalar();
	} catch(Exception e) { Console.WriteLine(e); }

	return exists == 1;
    }

    static bool chkInvalidEmail(string mail) {
	return !mail.Contains('@');
    }

    static string[] LoginData(string user) {
	string[] ret = new string[3];

	var sql = $"SELECT auth, totp, mail FROM clients WHERE name=@name";

	try {
	    using var cmd = new MySqlCommand(sql, sqlCon);
	    
	    cmd.Parameters.AddWithValue("@name", user);
	    cmd.Prepare();
	    using MySqlDataReader rdr = cmd.ExecuteReader();
	    rdr.Read();
	    ret[0] = rdr.GetString(0);
	    ret[1] = rdr.GetString(1);
	    ret[2] = rdr.GetString(2);
	    rdr.Close();
	} catch (Exception e) { Console.WriteLine(e); }

	return ret;
    }

    static string[] DataFromUsername(string user, string[] vars) {
	var sql = $"SELECT ";
	for(int i = 0; i < vars.Length-1; i++)
	    sql += (vars[i] + ", ");
	sql += (vars[vars.Length-1] + " FROM clients WHERE name=@name");

	Console.WriteLine(sql);
	using var cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@name", user);
	cmd.Prepare();
	using MySqlDataReader rdr = cmd.ExecuteReader();
	rdr.Read();

	List<string> ret = new List<string>();
	for(int i = 0; i < vars.Length; i++)
	    ret.Add(rdr.GetString(i));

	rdr.Close();
	return ret.ToArray();
    }

    static void CreateLoginHash(int id, string authHash) {
	string sql;
	MySqlCommand cmd;
	int ip = (int)request.RemoteEndPoint.Address.Address;

	bool exists = chkLoginHashExists(id, ip);

	if(exists) {
	    try {
		sql = $"UPDATE auths SET auth=@auth WHERE id=@id AND ip=@ip"; 

		cmd = new MySqlCommand(sql, sqlCon);
		cmd.Parameters.AddWithValue("@id", id);
		cmd.Parameters.AddWithValue("@ip", ip);
		cmd.Parameters.AddWithValue("@auth", authHash);

		cmd.Prepare();
		cmd.ExecuteNonQuery();
	    } catch(Exception e) { Console.WriteLine(e); }

	} else {
	    try {
		sql = $"INSERT INTO auths(id, ip, auth) VALUES(@id, @ip, @auth)"; 

		cmd = new MySqlCommand(sql, sqlCon);
		cmd.Parameters.AddWithValue("@id", id);
		cmd.Parameters.AddWithValue("@ip", ip);
		cmd.Parameters.AddWithValue("@auth", authHash);

		cmd.Prepare();
		cmd.ExecuteNonQuery();
	    } catch(Exception e) { Console.WriteLine(e); }
	}
    }

    static void CreateAccount(string user, string mail, string authHash, string totpHash) {
	MySqlCommand cmd;
	string sql;

	sql = "INSERT INTO clients(name, mail, totp) VALUES (@name, @mail, @totp)";
	cmd = new MySqlCommand(sql, sqlCon);

	cmd.Parameters.AddWithValue("@name", user);
	cmd.Parameters.AddWithValue("@mail", mail);
	cmd.Parameters.AddWithValue("@totp", totpHash);

	cmd.Prepare();
	cmd.ExecuteNonQuery();

	int id = GetUserIDS(new string[] { user })[0];
	CreateLoginHash(id, authHash);
    }

    static string GetCookieAuth(int ip, string user) {
	MySqlCommand cmd;
	string sql, auth;

	int id = GetUserIDS(new string[] { user })[0];

	sql = "SELECT auth FROM auths WHERE id=@id AND ip=@ip";
	cmd = new MySqlCommand(sql, sqlCon);

	cmd.Parameters.AddWithValue("@id", id);
	cmd.Parameters.AddWithValue("@ip", ip);

	auth = (string)cmd.ExecuteScalar();
	return auth;
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

    static string SendConfirmationMail(string user, string mail, string token) {
	return ERRS.OK;
	try {
	    var message = new MimeMessage();
	    message.From.Add (new MailboxAddress("noreply", "noreply@basilisk.sh"));
	    message.To.Add (new MailboxAddress(user, mail));
	    message.Subject = "Authentication Token";

	    message.Body = new TextPart("html") {
		Text = "Provide this token for your account creation: <b>" + token + "</b>",
	    };

	    using (var client = new SmtpClient()) {
		client.Connect ("smtp.porkbun.com", 587, false);

		client.Authenticate("noreply@basilisk.sh", mailPassword);

		client.Send (message);
		client.Disconnect (true);
	    }
	} catch {
	    sessions.Remove(user);
	    return ERRS.couldNotSendMail;
	}

	return ERRS.OK;
    }

    static string login_0() {
	string? user;
	user = request.Headers["User"];

	if(chkInvalidHeader(user)) return ERRS.invalidUsername;
	if(!chkRowColExists("name", user)) return ERRS.userDoesntExist;

	string[] data = DataFromUsername(user, new string[] { "mail" });
	string mail = data[0];

	long ip = request.RemoteEndPoint.Address.Address;
	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("LOG IN REQUEST \"" + user + "\" " + "(" + ip + ")");
	Console.ForegroundColor = ConsoleColor.White;

	TempUser tempUser = new TempUser();
	tempUser.mail = mail;
	tempUser.ip = ip;
	tempUser.token = "1234";

	SendConfirmationMail(user, mail, tempUser.token);

	if(sessions.ContainsKey(user)) {
	    if(request.RemoteEndPoint.Address.Address != sessions[user].ip)
		return ERRS.userAlreadyExists;
	    
	    sessions[user] = tempUser;
	} else {
	    sessions.Add(user, tempUser);
	}

	sessions[user].loginStep++;
	return (char)OnError.NOTHING + "";
    }

    static string login_1() {
	string? user, toke;
	user = request.Headers["User"];
	toke = request.Headers["Toke"];

	if(chkInvalidHeader(user)) return ERRS.userAlreadyExists;
	if(chkInvalidSession(user)) return ERRS.invalidSession;
	if(chkInvalidAuthStep(sessions[user].loginStep, 1)) return ERRS.authStepSkip;
	if(chkExpiredSession(user)) return ERRS.expiredSession;

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("COMPARING EMAIL TOKEN \"" + sessions[user].token + "\" WITH \"" + toke + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	if(sessions[user].token != toke) {
	    if(++sessions[user].attempts == 3) {
		sessions.Remove(user);
		Console.WriteLine("TOO MANY ATTEMPTS!");
		return ERRS.tooManyAttempts;
	    }

	    return ERRS.invalidToken;
	}

	sessions[user].attempts = 0;
	sessions[user].loginStep++;

	return ERRS.OK;
    }

    static string login_2() {
	string? user, totp;
	user = request.Headers["User"];
	totp = request.Headers["Totp"];

	if(chkInvalidHeader(user)) return ERRS.userAlreadyExists;
	if(chkInvalidSession(user)) return ERRS.invalidSession;
	if(chkInvalidAuthStep(sessions[user].loginStep, 2)) return ERRS.authStepSkip;
	if(chkExpiredSession(user)) return ERRS.expiredSession;

	string[] data = DataFromUsername(user, new string[] { "totp" });
	string totpEncrypted = data[0];

	Aes aes = Aes.Create();
	aes.KeySize = 128;
	aes.Key = secret;

	byte[] totpKey = aes.DecryptEcb(Convert.FromBase64String(totpEncrypted), PaddingMode.ANSIX923);

	var totp_cmp = new Totp(totpKey);
	var code = totp_cmp.ComputeTotp();
	bool ok = code == totp;

	Console.WriteLine("Comparing: " + totp + " | " + code + " (" + (ok ? "CORRECT" : "INCORRECT") + ")");
	
	if(!ok) {
	    if(++sessions[user].attempts == 3)
		return ERRS.tooManyAttempts;

	    return ERRS.invalidToken;
	}

//	string cmpAuth = GetCookieAuth(ip, user);
//	bool ok = BC.Verify(auth, cmpAuth);

	Cookie authCookie = new Cookie();
	authCookie.Expires = DateTime.UtcNow.AddYears(10);
	authCookie.Name = "auth";
	authCookie.Value = Gen128();

	Cookie userCookie = new Cookie();
	userCookie.Name = "user";
	userCookie.Value = user;

	response.Cookies.Add(authCookie);
	response.Cookies.Add(userCookie);

	string authHash = BC.HashPassword(authCookie.Value);
	int id = GetUserIDS(new string[] { user })[0];
	CreateLoginHash(id, authHash);

	return (char)OnError.NOTHING + "";
    }

    static string auth_0() {
	string? user, mail;
	user = request.Headers["User"];
	mail = request.Headers["Mail"];

	if(chkInvalidHeader(user)) return ERRS.invalidUsername;
	if(chkInvalidHeader(mail)) return ERRS.invalidMail;
	if(chkInvalidEmail(mail)) return ERRS.invalidMail;
	if(chkIsNotAlphaNum(user)) return ERRS.notAlphaNumerical;
	if(chkRowColExists("name", user)) return ERRS.userAlreadyExists;
	if(chkRowColExists("mail", mail)) return ERRS.mailAlreadyExists;

	long ip = request.RemoteEndPoint.Address.Address;
	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("AUTHENTICATING \"" + user + "\" " + "(" + ip + ")");
	Console.ForegroundColor = ConsoleColor.White;

	TempUser tempUser = new TempUser();
	tempUser.mail = mail;
	tempUser.ip = ip;
	tempUser.token = "1234";
	
	if(sessions.ContainsKey(user)) {
	    if(request.RemoteEndPoint.Address.Address != sessions[user].ip)
		return ERRS.userAlreadyExists;

	    sessions[user] = tempUser;
	} else {
	    sessions.Add(user, tempUser);
	}

	SendConfirmationMail(user, mail, tempUser.token);

	sessions[user].authStep++;
	return (char)OnError.NOTHING + "";
    }

    static string auth_1() {
	string? user, toke;
	user = request.Headers["User"];
	toke = request.Headers["Toke"];

	if(chkInvalidHeader(user)) return ERRS.userAlreadyExists;
	if(chkInvalidSession(user)) return ERRS.invalidSession;
	if(chkInvalidAuthStep(sessions[user].authStep, 1)) return ERRS.authStepSkip;
	if(chkExpiredSession(user)) return ERRS.expiredSession;

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine("COMPARING EMAIL TOKEN \"" + sessions[user].token + "\" WITH \"" + toke + "\"");
	Console.ForegroundColor = ConsoleColor.White;

	if(sessions[user].token != toke) {
	    if(++sessions[user].attempts == 3) {
		sessions.Remove(user);
		Console.WriteLine("TOO MANY ATTEMPTS!");
		return ERRS.tooManyAttempts;
	    }

	    return ERRS.invalidToken;
	}

	sessions[user].attempts = 0;
	sessions[user].authStep++;
	return (char)OnError.NOTHING + "";
    }

    static string auth_2() {
	string? user;
	user = request.Headers["User"];

	if(chkInvalidHeader(user)) return ERRS.invalidUsername;
	if(chkInvalidSession(user)) return ERRS.invalidSession;
	if(chkInvalidAuthStep(sessions[user].authStep, 2)) return ERRS.authStepSkip;
	if(chkExpiredSession(user)) return ERRS.expiredSession;

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

	if(chkInvalidHeader(user)) return ERRS.invalidUsername;
	if(chkInvalidHeader(totp)) return ERRS.invalidToken;
	if(chkInvalidSession(user)) return ERRS.invalidSession;
	if(chkInvalidAuthStep(sessions[user].authStep, 3)) return ERRS.authStepSkip;
	if(chkExpiredSession(user)) return ERRS.expiredSession;

	string totp_cmp = sessions[user].totp.ComputeTotp();
	totp = totp.Replace(" ", "");
	bool ok = totp_cmp == totp;

	Console.WriteLine("Comparing: " + totp + " | " + totp_cmp + " (" + (ok ? "CORRECT" : "INCORRECT") + ")");

	if(!ok) {
	    if(++sessions[user].attempts == 3)
		return ERRS.tooManyAttempts;

	    return ERRS.invalidToken;
	}

	/* Generate 128 bit password and send to client as cookie */
	Cookie authCookie = new Cookie();
	authCookie.Expires = DateTime.UtcNow.AddYears(10);
	authCookie.Name = "auth";
	authCookie.Value = Gen128();

	Cookie userCookie = new Cookie();
	userCookie.Name = "user";
	userCookie.Value = user;

	response.Cookies.Add(authCookie);
	response.Cookies.Add(userCookie);

	/* Hash the 128 bit password */
	string authHash = BC.HashPassword(authCookie.Value);

	/* Encrypt TOTP secret */
	Aes aes = Aes.Create();
	aes.KeySize = 128;
	aes.Key = secret;

	byte[] totpBytes = Base32Encoding.ToBytes(sessions[user].totpBase32);
	string encrypt64 = Convert.ToBase64String(aes.EncryptEcb(totpBytes, PaddingMode.ANSIX923));

	CreateAccount(user, sessions[user].mail, authHash, encrypt64);

	sessions.Remove(user);
	return (char)OnError.NOTHING + "";
    }

    static bool AutoLogin(out string outUser) {
	string? user, auth;

	outUser = null;
	Cookie userCookie = request.Cookies["user"];
	Cookie authCookie = request.Cookies["auth"];

	if(userCookie == null)
	    return false;

	if(authCookie == null)
	    return false;

	user = userCookie.Value;
	auth = authCookie.Value;
	outUser = user;

	Console.WriteLine("1");
	if(chkInvalidHeader(user))
	    return false;

	Console.WriteLine("2");
	if(chkInvalidHeader(auth))
	    return false;

	Console.WriteLine("3");
	int ip = (int)request.RemoteEndPoint.Address.Address;
	string cmpAuth = GetCookieAuth(ip, user);

	if(string.IsNullOrEmpty(cmpAuth))
	    return false;

	bool ok = false;
	try {
	    ok = BC.Verify(auth, cmpAuth);
	} catch(Exception e) { Console.WriteLine(e); }

	return ok;
    }

    static bool UserHasSentFriendRequest(int sender, int recipient) {
	string sql;
	MySqlCommand cmd;
	MySqlDataReader rdr;

	sql = $"SELECT COUNT(DISTINCT sender) FROM friendreqs WHERE sender=@sender AND recipient=@recipient";

	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@sender"   , sender);
	cmd.Parameters.AddWithValue("@recipient", recipient);

	cmd.Prepare();
	cmd.ExecuteReader();
	
	rdr = cmd.ExecuteReader();
	rdr.Read();

	bool val = rdr.GetInt32(0) == 1;
	rdr.Close();
	return val;
    }

    static int[] GetUserIDS(string[] names) {
	string sql;
	MySqlCommand cmd;
	int[] ret = new int[names.Length];
	
	sql = $"SELECT id FROM clients WHERE name=@name";
	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@name", names[0]);
	ret[0] = (int)cmd.ExecuteScalar();
	for(int i = 1; i < names.Length; i++) {
	    cmd.Parameters[0].Value = names[i];
	    ret[i] = (int)cmd.ExecuteScalar();
	}

	return ret;
    }

    static string NameFromID(int ID) {
	string sql;
	MySqlCommand cmd;
	
	sql = $"SELECT name FROM clients WHERE id=@id";
	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@id", ID);

	return (string)cmd.ExecuteScalar();
    }

    static void AcceptFriendRequest(int sender, int recipient) {
	string sql;
	MySqlCommand cmd;

	sql = $"UPDATE friends SET type=@type WHERE user0=@user0 AND user1=@user1";

	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@type" , (sbyte)FriendType.FRIENDS);
	cmd.Parameters.AddWithValue("@user0", sender);
	cmd.Parameters.AddWithValue("@user1", recipient);
	cmd.ExecuteNonQuery();
	
	Console.WriteLine(sender + " and " + recipient + " are now friends");
    }

    static string Befriend() {
	bool loggedIn = AutoLogin(out var user);
	if(!loggedIn) {
	    Console.WriteLine("Not logged in");
	    return ERRS.notLoggedIn;
	}

	string? friend;
	friend = request.Headers["Friend"];

	Console.ForegroundColor = ConsoleColor.Cyan;
	Console.WriteLine(user + " sent a friend request to " + friend);
	Console.ForegroundColor = ConsoleColor.White;

	/* Get user IDs */
	int senderID, recipientID;

	try {
	    int[] IDs = GetUserIDS(new string[] { user, friend });
	    senderID = IDs[0];
	    recipientID = IDs[1];
	} catch {
	    return ERRS.userNotFound;
	}

	/* Check if request already exists */
	string sql;
	MySqlCommand cmd;
	int user0, user1;
	sbyte type;

	sql = $"SELECT * FROM friends WHERE user0=@sender AND user1=@recipient OR user1=@sender AND user0=@recipient";

	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@sender"   , senderID);
	cmd.Parameters.AddWithValue("@recipient", recipientID);

	using MySqlDataReader rdr = cmd.ExecuteReader();
	if(rdr.HasRows) {
	    rdr.Read();
	    user0 = rdr.GetInt32(0);
	    user1 = rdr.GetInt32(1);
	    type  = rdr.GetSByte(2);
	    rdr.Close();

	    /* If same user sent same request more than once */
	    if(user0 == senderID) {
		Console.WriteLine("Request already sent");
		return ERRS.friendReqAlreadySent;
	    }

	    /* Create a friendship if both parties have sent a friend request to eachother */
	    AcceptFriendRequest(user0, user1);
	    return (char)OnError.NOTHING + "1";
	}
	rdr.Close();

	/* Create friend request */
	Console.WriteLine("Sending friend request...");
	sql = $"INSERT INTO friends VALUES(@sender, @recipient, @type)";
	
	cmd = new MySqlCommand(sql, sqlCon);
	cmd.Parameters.AddWithValue("@sender"   , senderID);
	cmd.Parameters.AddWithValue("@recipient", recipientID);
	cmd.Parameters.AddWithValue("@type", (sbyte)FriendType.REQUEST);
	cmd.ExecuteNonQuery();
	Console.WriteLine("Sent!");

	return (char)OnError.NOTHING + "0";
    }

    static string ChkStatus() {
    	bool loggedIn = AutoLogin(out var user);
	if(!loggedIn)
	    return ERRS.notLoggedIn;

	// Get friend requests
	string sql;
	MySqlCommand cmd;

	int ID = GetUserIDS(new string[] { user })[0];

	sql = $"SELECT user0, type FROM friends WHERE user1=@id LIMIT 8";

	string res = "0";

	int[] reqIDs = new int[8];
	int[] types = new int[8];
	int count = 0;

	try {
	    cmd = new MySqlCommand(sql, sqlCon);
	    cmd.Parameters.AddWithValue("@id", ID);

	    using MySqlDataReader rdr = cmd.ExecuteReader();

	    for(count = 0; rdr.Read(); count++) {
		reqIDs[count] = rdr.GetInt32(0);
		types[count]  = rdr.GetInt32(1);
	    }
	    rdr.Close();
	} catch(Exception e) {Console.WriteLine(e);}

	for(int i = 0; i < count; i++) {
	    if(types[i] == (int)FriendType.REQUEST)
		res += " + Friend request from \"" + NameFromID(reqIDs[i]) + "\"\n";
	}

	return res;
    }

    static void listen(HttpListener listener) {
	context = listener.GetContext();
        request = context.Request;
        response = context.Response;
        output = response.OutputStream;

	string? type = request.Headers["Type"];
	string ret = (char)OnError.NOTHING + "Unknown type";

	Console.WriteLine("TYPE_: " + type);
	try {
	    switch(type) {
		case "auth_0": ret = auth_0(); break;
		case "auth_1": ret = auth_1(); break;
		case "auth_2": ret = auth_2(); break;
		case "auth_3": ret = auth_3(); break;

		case "login_0": ret = login_0(); break;
		case "login_1": ret = login_1(); break;
		case "login_2": ret = login_2(); break;

		case "befriend": ret = Befriend(); break;
		case "status"  : ret = ChkStatus(); break;
		default: break;
	    }
	} catch {};

	closeOutput(ret);
	return;
    }

    public static void Main() {
        HttpListener listener = new HttpListener();

	string[] lines = File.ReadAllLines("secrets.txt");
	mailPassword = lines[0];
	secret = Encoding.UTF8.GetBytes(lines[1]);

	Console.WriteLine("Connecting to SQL...");
	string cs = lines[2];
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
