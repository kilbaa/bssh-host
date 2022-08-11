﻿using System.Net;
using System.Text;

class Program {
    static void send_string(HttpListenerResponse response, string responseString, System.IO.Stream output){
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        output.Write(buffer);
    }
    
    static void send_package(string package, HttpListenerResponse response, System.IO.Stream output){
        if(Directory.Exists(package)){
            Console.WriteLine("ha");
        }
        string[] files = 
            Directory.GetFiles(package);
        Console.WriteLine(files);

        if(File.Exists(package + ".txt")){
            byte[] file = File.ReadAllBytes(package + ".txt");
            output.Write(file);

        }
        
    }
    static void update_package(){

    }
    static void listen(HttpListener listener){
        HttpListenerContext context = listener.GetContext();
        HttpListenerRequest request = context.Request;
        HttpListenerResponse response = context.Response;
        System.IO.Stream output = response.OutputStream;
        response.AddHeader("info", "haha");

        string package = "";
        string message = "";
        string? test = request.Headers["name"]; 
        if(test is not null){
            package = test;
            Console.WriteLine(request.Headers["type"]);
            Console.WriteLine("Package name : " + package);


            if(package == "" && package == " "){ // If the client somehow sent no name or blank space as the package name
                Console.WriteLine("No package declared");
                message += "No package Declared\n";
            //} else if(!File.Exists(package + ".txt")){// If the client sent a package name but it doesn't exist
            //    Console.WriteLine("Package " + package + "  does not exist!");
            //    message += "Package " + package + " Does not exist!";
            }else{
                if(request.HttpMethod == "GET"){ // If the client is requesting something (thereby GET)
                message += "Get fked\n";

                if(request.Headers["type"] == "get-pkg"){ // If the type the client is asking for is get a package (What command they are asking off from)
                    send_package(package, response, output);
                }
                }else{
                    Console.WriteLine("Post fked");
                    message += "Post fked\n";
                }
            }
        }else{
            message += "No package name sent";
        }

        

        send_string(response, message, output);
        Console.WriteLine("Text sent : " + message);
        output.Close();
    }
    public static void Main() {
        HttpListener listener = new HttpListener();

        listener.Prefixes.Add("http://*:8001/");

        listener.Start();
        while(true){
            Console.WriteLine("\n\nListening... ");
            listen(listener);
        }
        //listener.Close();
        
    }

} // bssh get-pkg name
