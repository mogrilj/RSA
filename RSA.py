import math
import random
import datetime
import json
import os

#creating global values for blocklength, the database, the base number and the keylength

def getPrimes(rng):
	primeNumbers= [2]
	#looping from two to the given range
	for i in range(2,rng):
		isPrime = True
		#looping through all the already found primes
		for x in primeNumbers:
                        #checking if the new number an the given prime Numbers GCD is >1
                        #if that is true, the given number i is not prime
			if math.gcd(x,i)>1:
				isPrime = False
			#if I is not prime break the loop
			if isPrime == False:
				break
		# if i is prime add to the list
		if isPrime:
			primeNumbers.append(i)
	return primeNumbers
def getListOfCoprimes(Phi,rng):
    coPrimes = []
    #looping through numbers in a given range rng
    for i in range(2,rng):
        #chechking if the only common factor of X and I is 1. If so, they are coprime
        if math.gcd(Phi,i) == 1:
            coPrimes.append(i)
    return coPrimes

def getD(E,PHI,Coprimes):
    for d in Coprimes:
        #chech all coprimes of Phi so that e*d % Phi == 1
        if E*d % PHI == 1:
            return d
def hash(text,username):
    hashCode  = 0
    for letter in text:
        hashCode = ord(letter)+hashCode
    for letter in username:
        hashCode = hashCode+ord(letter)
    return hashCode
def generateKeys(keylength):
    #generate two unique index numbers for the list of primes
    primes = getPrimes(keylength)
    indexNums = random.sample(range(0,len(primes)-1),2)
    #assining primes to p and q and calculating N and PHI
    P = primes[indexNums[0]]
    Q = primes[indexNums[1]]
    N = P*Q
    PHI = (P-1)*(Q-1)
    #Calculating E by finding coprimes to PHI in the rang so that 1<E<PHI
    coPrimesOfPHI = getListOfCoprimes(PHI,PHI)
    E = coPrimesOfPHI[random.randint(0,len(coPrimesOfPHI)-1)]
    #calculating D
    D = getD(E,PHI,coPrimesOfPHI)
    Key = [[E,N],[D,N,P,Q]]
    return Key
def encryptMessage(publicKey,message,blocklength,base):
    #formating the text to fit blocklength by adding spaces at the end
    for i in range(blocklength-(len(message) % blocklength)):
        message = message + " "
    #splitting message into same sized parts
    splitMessage = []
    tempString = ""
    for letter in message:
        tempString = tempString+ letter
        if len(tempString) % blocklength == 0:
            splitMessage.append(tempString)
            tempString = ""
    #converting the blocks into ascii lists
    asciiList = []
    #looping through the blocks
    for text in splitMessage:
        tempList = []
        #looping through the letters in the blocks and converting them into ascii
        for letter in text:
            tempList.append(ord(letter))
        asciiList.append(tempList)

    #converting each block of ascii into a base 256 number system
    base256Numbers = []
    for block in asciiList:
        tempSum = 0
        index = 1
        for number in block:
            tempSum = tempSum + number*base**(blocklength-index)
            index = index + 1
        base256Numbers.append(tempSum)

    #encrypting the blocks using the RSA system
    encryptedValues = []
    for number in base256Numbers:
        encryptedValues.append(number**publicKey[0] % publicKey[1])
    #adding all values together as a string with -
    encryptetMessage = ""
    for value in encryptedValues:
        encryptetMessage = encryptetMessage + str(value) + " "
    return  encryptetMessage.strip()
def decryptMessage(message,privateKey,blocklength,base):
    #translating the message from string into list of numbers
    encryptetMessage = [int(block)for block in message.split(" ")]

    #encrypting the numbers from the list with the RS system
    base256Numbers = []
    for number in encryptetMessage:
        base256Numbers.append(number**privateKey[0] % privateKey[1])
    #converting the base256 values into ascii values

    asciiList = []
    for number in base256Numbers:
        tempAsciiList = []
        for i in range(blocklength):
            tempAsciiList.append(int((number % base**(blocklength-i))/base**(blocklength-i-1)))
        asciiList.append(tempAsciiList)

    #converting the ascii values to string
    decryptetMessage = ""
    for block in asciiList:

        for value in block:
            decryptetMessage = decryptetMessage + chr(value)
    decryptetMessage = decryptetMessage.strip()
    return decryptetMessage

def saveKey(Key,username,password):
    #creating inbox file at username.txt
    open(username+".txt","w+")
    #opening the file where to safe the things and copy the old things out
    file = open("db.txt","r")
    oldDb = file.read();
    file.close()
    #creating dictonary with the information of the key
    userDictonary = {
        "username" : username,
        "password" : hash(password,username),
        "publicKey" : Key[0],#E,N
        "privateKey" : Key[1]#D,N,P,Q
    }
    #safe the data in the file

    file = open("db.txt","w")
    file.write(oldDb+json.dumps(userDictonary)+"\n")
    file.close()

def getUserData(username,password):
    #open the database and get all data
    dataBase = open("db.txt","r")
    data = dataBase.read()
    dataBase.close()
    userData = {}
    #looping through the data and finding the username password match
    for line in data.splitlines():
        tempUserData = json.loads(line)
        if tempUserData["username"] == username and tempUserData["password"] == hash(password,username):
            userData = tempUserData

    if userData == {}:
        print("No account with this username and password has been found!")
        return None
    else:

        print("Login was succssesful!")
        return userData

def getPublicKeyByUsername(username):

    publicKey = None
    #getting the database

    database = open("db.txt","r")
    data = database.read()
    #creating search query

    #looping through the database to find the query
    for line in data.splitlines():
        if json.loads(line)["username"] == username:
            publicKey = json.loads(line)["publicKey"]
            break
    if publicKey == None:
        print("No user with the username:"+username+" has been found!")
        return  None
    else:
        print("Public Key aquirred!")

        return publicKey

def checkUsername(username):
    isUsed= False
    #get database
    database = open("db.txt","r")
    data = database.read()

    #looping through the db
    for line in data.splitlines():
        #casting the string into a dict
        info = json.loads(line)
        if info["username"] == username:
            isUsed = True

    return isUsed

def sendMessage(reciverUsername,senderUsername,message):
    #opening the recivers inbox
    inbox = open(reciverUsername+".txt","r")
    inboxData = inbox.read()
    inbox.close()
    #opening the inbox to write
    inbox = open(reciverUsername+".txt","w")
    #creating the message as a dict with username and message
    messageAsDict = {"message" : message, "sender" : senderUsername}
    #adding the message to the inbox
    inbox.write(inboxData+json.dumps(messageAsDict)+"\n")
    inbox.close()
    print("message has been transmitted!")

def readInbox(username,privateKey):
    #opening inbox
    inbox = open(username+".txt","r")
    inboxData = inbox.read()
    #looping and printing the messages
    for line in inboxData.splitlines():
        messageAsDict = json.loads(line)
        print(decryptMessage(messageAsDict["message"],privateKey,1,200)+"              "+messageAsDict["sender"])

def checkIfKeyIsWorking(key):
    testMessage = "You fucked with squirrels morty!"
    if decryptMessage(encryptMessage(key[0],testMessage,1,200),key[1],1,200) == testMessage:
        return True
    else:
        return False

def clearDatabase():
    db = open("db.txt","w")
    db.write("")
    db.close()
    os.system("del "+os.getcwd()+"\\"+"*.txt")
    open("db.txt","w+").close()
    print("database has been cleared")


def showAllUsers():
    db = open("db.txt","r")
    data = db.read()
    for line in data.splitlines():
        print(json.loads(line)["username"])

def clearInbox(username):
    inbox = open(username+".txt","w")
    inbox.write("")
    inbox.close()
    print("Inbox was cleared sucsessfully!")
def getListOfCommands():
    listOfCommands = ["help","encrypt","decrypt","login","create account",
                      "send message","read inbox","user data","clear database",
                      "show all users","logout",
                      "clear inbox"]
    return listOfCommands


def controlCenter():
    userData = None
    while True:
        command = input("Enter command:").strip()
        if command == "help":
            for cmd in getListOfCommands():
                print(cmd)


        if command == "login":
            #calling the function that gets the user data
            userData = getUserData(input("username:").strip(),input("password:").strip())


        if command == "encrypt":
            #getting the public key of the encryption
            publicKeyOfReciever = getPublicKeyByUsername(input("username of reeciver:").strip())
            if publicKeyOfReciever != None:
                #encrypting the message
                encryptedMessage = encryptMessage(publicKeyOfReciever,input("message:").strip(),1,200)
                print(encryptedMessage)
            else:
                print("The public Key is invalid!")


        if command == "decrypt":
            if userData != None:
                message = decryptMessage(input("enter encryptedMessage:"),userData["privateKey"],1,200)
                print(message)
            else:
                print("login first!")


        if command == "create account":
            username = input("enter username:").strip()
            #checking if username is already used
            if  checkUsername(username):
              print("username is already used!")
            else:
                password = input("enter password:").strip()
                isKeyWorking = False
                while not isKeyWorking:
                    key = generateKeys(2**8)
                    isKeyWorking = checkIfKeyIsWorking(key)
                saveKey(key,username,password)
            print("account created sucsessfuly!")

        if command == "send message":
            if userData != None:
                    reciverUsername = input("enter reciver:").strip()
                    message = encryptMessage(getPublicKeyByUsername(reciverUsername),input("enter message:").strip(),1,200)
                    sendMessage(reciverUsername,userData["username"],message)
            else:
                print("You have to login first")

        if command == "read inbox":

            if userData != None:

                readInbox(userData["username"],userData["privateKey"])
            else:
                print("you have too login first!")
        if command == "user data":
            print(userData)
        if command == "clear database":
            if input("enter master-password:") == "Nana and Bobo":
                clearDatabase()
        if command == "show all users":
            showAllUsers()

        if command == "logout":
            userData = None
            print("you are now logged out!")

        if command == "clear inbox":
            if userData != None:
                if input("enter password:").strip() == userData["password"]:
                    clearInbox(userData["username"])
                else:
                    print("This is not the correct password! Please try again!")
            else:
                print("you have to login first!")
        if command == "clear":
            os.system("cls")
controlCenter()


