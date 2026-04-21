import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import math
import socket
import os
from Crypto.Cipher import AES

CLIENT_PASSWORD = os.environ.get("SERVER_PASSWORD") ##Retrieve the password from the OS, which will be feeded in the OS manually. 

SHARED_KEY = os.environ.get("NETWORK_KEY") ## We will retrive the key from the OS, after we stroe it there
SHARED_KEY = SHARED_KEY.encode("utf-8")
class SimpleNetworkClient :
    def __init__(self, port1, port2) :
        #self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        '''self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
                                self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")'''
        '''plt.xticks(range(30), self.times, rotation=45)
                                plt.ylim((20,50))
                                plt.legend(handles=[self.infLn, self.incLn])'''
        self.infPort = port1
        self.incPort = port2

        self.infToken = None
        self.incToken = None

        '''self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
                                self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)'''
    def encrypt(self,message):
        cipher = AES.new(SHARED_KEY, AES.MODE_EAX) # Random Nonce is generated automatically
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
        return cipher.nonce + tag + ciphertext

    def decrypt(self, message):
        nonce = message[:16]
        tag = message[16:32]
        ciphertext = message[32:]
        cipher = AES.new(SHARED_KEY, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            '''plt.xticks(range(30), self.times,rotation = 45)
                                                plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))'''

    def getTemperatureFromPort(self, p, tok) :
        payload = self.encrypt(tok + ";GET_TEMP")
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", p))
        #s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        m = self.decrypt(msg)
        return (float(m))
   

    def authenticate(self, p, pw) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        plaintext="AUTH %s;" % pw.decode("utf-8")
        ciphertext=self.encrypt(plaintext)
        s.sendto(ciphertext, ("127.0.0.1", p))
        msg, addr = s.recvfrom(1024)
        return self.decrypt(msg).strip().encode("utf-8")

    def setTemperatureC(self, p, tok):
        payload = self.encrypt(tok + ";SET_DEGC")
        try:
            s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            s.sendto(payload, ("127.0.0.1", p))
        except Exception as ex:
            return False
        return True

    def setTemperatureF(self, p, tok):
        payload = self.encrypt(tok + ";SET_DEGF")
        print(payload)
        try:
            s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            s.sendto(payload, ("127.0.0.1", p))
        except Exception as ex:
            return False
        return True

    def setTemperatureK(self, p, tok):
        payload = self.encrypt(tok + ";SET_DEGK")
        try:
            s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            s.sendto(payload, ("127.0.0.1", p))
        except Exception as ex:
            return False
        return True

    def updateInfTemp(self, p, tok) :
        self.updateTime()
        if self.infToken is None : #not yet authenticated
            self.infToken = self.authenticate(self.infPort, CLIENT_PASSWORD.encode("utf-8"))
        self.infTemps.append(self.getTemperatureFromPort(p, tok)-273)
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, p, tok) :
        self.updateTime()
        if self.incToken is None : #not yet authenticated
            self.incToken = self.authenticate(self.incPort, CLIENT_PASSWORD.encode("utf-8"))

        self.incTemps.append(self.getTemperatureFromPort(p, tok)-273)
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

'''snc = SimpleNetworkClient(23456, 23457)

plt.grid()
plt.show()'''
