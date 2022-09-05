import sys
import ipaddress as ip
import base64
import os
import configparser
import time
from client import cli
from client.VER import __version__


def valIP(nodeIP: str) -> None:
    try:
        nodeIP = nodeIP.replace("http://","")
        nodeIP= nodeIP.split(":",1)[0]
        ip_obj = ip.ip_address(nodeIP) #Creates IP object using the ipaddress module, which automatically throws a value error if the IP is improper
    except ValueError:
        print("Invalid IP")
        sys.exit()

def valPort(port: str) -> None:
    try:
        port = int(port)
        if port < 0 or port > 65535: raise ValueError
    except ValueError:
        print("Invalid Port. Please enter IP:PORT")
        sys.exit()

#Simple helper method to see if opening a file is possible
def valFile(path:str) -> None:
    try:
        f= open (path)
    except OSError:
        print("Something went wrong reading the file")
        sys.exit()

def valOut(path:str) -> None:
    try:
        f=open(path, 'w')
    except FileNotFoundError:
        print("Error making output file")
        sys.exit()

#Method to validate the arguments passed in
def valArgs(args:list) -> None:
    try:
        valid_commands = [ "version" , "connect" , "set" , "inc" ,"dec" , "trans",
                            "show", "list" , "execute" , "exit","key","validator", "output" ]

        if args[1].lower().strip() not in valid_commands : raise NameError

        if len(args) < 3 and 'list' not in args and 'version' not in args : raise IndexError

        if (args[1] == "connect" or args[1]=="output") and len(args) != 3:
            raise IndexError

        if args[1] in ["dec","inc","set","trans"]:
            if args[1] != "trans" and len(args) != 4 and len(args)!= 5 : raise IndexError
            config.read("config/config.ini")
            user_info = config["user_info"]
            global PK_path
            PK_path = user_info["pk_path"]

            if args[1] != "trans" : 
                valToken(args[3])
                if len(args)==5: #If the length of the arg list is 5, and it's valid it means that the user passed in a wait parameter
                    valWait(args[4])
                    time.sleep(int(args[4]))
            else: 
                if len(args) != 6 and len(args)!=5 : raise IndexError
                
                valToken(args[4])
                if len(args)==6 : 
                    valWait(args[5]) #Wait Parameter 
                    time.sleep(int(args[5]))
            
        if args[1] == "show" :
            if len(args)!=3 and len(args)!=4 :raise IndexError
            if len(args) == 4: 
                valWait(args[3]) #Wait Paramater
                time.sleep(int(args[3]))

        if args[1] == "list":
            if len(args)!=2 and len(args)!=3: raise IndexError
            if len(args) == 3:
                valWait(args[2])
                time.sleep(int(args[3]))
        
        if args[1] == "output" :
            valOut(args[2])

    except IndexError:
        print("Invalid number of arguments.")
        sys.exit()
    except NameError:
        print("Invalid Command")
        sys.exit()
    except KeyError:
        print("No Private Key found, add it with bgtc key [PATH]")
        sys.exit()
#Runs on the first "connect" command, requires seperate logic from updating IP
def initIP():
    try:
       connect = arguments[1]
       if connect != "connect" : raise NameError
       if len(arguments) > 3  : raise IndexError
      #TODO: Add support for https and SSH  
       valIP(arguments[2])
       
       if ":" not in arguments[2]:
           print("Please provide Port")
           sys.exit()

       valPort(arguments[2].split(":",1)[1])

       config.add_section("user_info")
       config.set("user_info", "node_ip" , arguments[2])
       
       if not os.path.isdir("config"): os.makedirs("config") 
       with open("config/config.ini","w") as file:
           config.write(file)
   
    except IndexError:
        print("Invalid number of arguments")
        sys.exit()
    except NameError:
        print('Not connected to any Node, run "bgtc connect"')
        sys.exit()
    except OSError:
        print("Something went wrong when writing the config file")
        sys.exit()
        
def updateIP(socket:str) -> None:
    config.read("config/config.ini")
    user_info = config["user_info"]
    
    ip_port=socket.split(":",1)
    valIP(ip_port[0])
    valPort(ip_port[1])

    user_info["node_ip"] = socket
    try:
        with open("config/config.ini","w") as cf:
            config.write(cf)
    except OSError:
        print("Someting went wrong modifing the config file")
        sys.exit()

def setOutput(out: str):
    config.read("config/config.ini")
    if not config.has_option("user_info","output") : config.set("user_info","output",os.path.abspath(out))
    else : config["user_info"]["output"] =  os.path.abspath(out)

    with open("config/config.ini","w") as cf:
        config.write(cf)


def getKey(path: str) -> str :
    try:
        print(path)
        with open(path) as f:
            KF = f.read().strip()
            f.close()
        KF = KF.replace("-----BEGIN EC PRIVATE KEY-----","") #OPENSSL adds these lines to the top and bottom, we want to to remove them
        KF = KF.replace("-----END EC PRIVATE KEY-----" , "")
        KF= base64.b64decode(KF).hex()
        return KF
    except OSError as e:
        print("Failed to Read Private Key")
        sys.exit()
        

def writeKey(path:str):
    #We don't do any verifing here, since it should have already been verified
    #by valArgs and getKey
    config.read("config/config.ini")
    
    if not config.has_option("user_info","pk_path"):
        config.set("user_info", "pk_path",os.path.abspath(path))
    else:
        config["user_info"]["pk_path"] = os.path.abspath(path)
    with open("config/config.ini","w") as cf:
        config.write(cf)
    
def valWait(wait:str):
    try:
        wait=int(wait)
        if wait <0 or wait > 70: raise ValueError
    except ValueError:
        print("Wait must be an integer between 0 and 70")
        sys.exit()

def valToken(token:str):
    try:
        token=int(token)
        if token <0 or token > 2**32 -1 : raise ValueError
    except ValueError:
        print("Token must be a non-negative integer between 0 and 2^32")
        sys.exit()


def out(result):
    if config.has_option("user_option", "output") : 
            with open(config["user_option"]["output"],'w') as f:
                f.write(result)
                sys.exit()
    else: 
        print("flag")
        print(result) 


def main():
    try:
        if sys.argv[1] =="execute":
            file = open(sys.argv[2] , 'r')
            lines = file.readlines()
            for l in lines : 
                run(l.split( " "))
        else:
            run(sys.argv)
    except IndexError:
        run(sys.argv)
#Runs the command passed into it
def run(args:list):
    global arguments
    arguments=args
    global config
    config = configparser.ConfigParser()
    
    valArgs(arguments)

    #These commands do not require to be connected to any Node
    if arguments[1] == "version":
        print(__version__)
        sys.exit()
    if arguments[1] == "output" :
        setOutput(args[2])
        print ("output set")
        sys.exit


    if not os.path.isfile("config/config.ini"): initIP()
     
    if arguments[1] == "key" : 
        global PK
        writeKey(arguments[2])
        sys.exit()
    
    if arguments[1] == "validator" :
        valFile("config/config.ini")
        config.set("user_info","validator_ip",arguments[2])
        with open("config/config.ini","w") as cf:
            config.write(cf)


    config.read("config/config.ini")

    #Perhaps upgarading to Python 3.10 for the match statment is worth it
    if arguments[1] == "connect" : 
        updateIP(arguments[2])
        nodeIP=arguments[2].split(":",1)
        
        #It's important to note that the socket doesn't stay open after the program exits.
        errno=cli.connect(nodeIP[0], int(nodeIP[1]))

        if errno != 0 : 
            print(f"Something went wrong. Errno:{errno}") 
            sys.exit()
        print("Sucessfully connected.")
    
    if arguments[1] in ["inc","dec","set","trans"]:
        if arguments[1] == "trans" : 
            to = arguments[3]
            val = arguments[4]
        else: 
            to = None
            val = arguments[3]
        PK=getKey(PK_path)
        result = cli.send(IP= config["user_info"]["node_ip"].replace("http://","") \
                , verb =arguments[1] , wal = arguments[2], value =val, PK=PK, to=to )
        out(result)
           
    if arguments[1] == "show" : cli.show(config["user_info"]["node_ip"],arguments[2])
    if arguments[1] == "exit" : sys.exit()
    if arguments[1] == "list":
        config.read("config/config.ini")
        if not config.has_option("user_info","validator_ip"):
            print("Validator IP has not been set. Please run the 'validator' command \
                    followed by the IP of the validator. The deafult validator is \
                    'tcp://validator-dgt-c1-1:8108' , please consult the documentarion (section 3.2) \
                    for how to find the validator ip.")
        sys.exit()
        cli.List(config["user_info"]["node_ip"].replace("http://",""),config["user_info"]["validator_ip"])
  

if __name__ == '__main__':
        main() 
