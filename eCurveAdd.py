"""
Series of functions to do basic encrytion/decryption using elliptical curves for deciding on a key.
I was working off of this book: An Introduction to Mathematical Cryptography (Undergraduate Texts in Mathematics) by Jeffrey Hoffstein
https://www.amazon.com/Introduction-Mathematical-Cryptography-Undergraduate-Mathematics/dp/1493939386
"""

import hashlib

class curve:
    def __init__(self, a, b, p):        #Weierstrass curve form
        self.a = a                      #stores the a and b integers and the prime that forms the field
        self.b = b
        self.p = p

    def whatC(self):                    #prints curve
        print("Curve: y^2 mod", self.p, "= x^3 +", self.a, "x +", self.b, "mod", self.p,)

    def isGroup(self):                  #confirms the curve forms a group over the field
        if ( (4 * self.a ** 3) + (27 * self.b ** 2) ) % self.p == 0:
            return False
        return True

class point:
    def __init__(self, x, y, c):        #describes the point and the associated curve being used
        self.x = x
        self.y = y
        self.c = c

    def pointValue(self):               #Computes the LHS and RHS values of the point.
        L = (self.y ** 2) % ((self.c).p)
        R = (self.x ** 3 + ( (self.c).a ) * (self.x) + ( (self.c).b )) % ( (self.c).p )
        V = [L, R]
        return V

    def pointValid(self):               #Checks to see if LHS==RHS and therefore confirms the point is on the curve 
        V = self.pointValue()               
        if V[0] == V[1]:
            return True
        return False

    def pointDisplay(self):
        print("x = ", self.x, " y = ", self.y)
        return
        

def eAdd(P, Q):                         #adds 2 points by using the slope to find where the line intersects and returns the negation of that point
    R = point(0,0,P.c)
    if (P.x == 0 and P.y == 0) and (Q.x == 0 and Q.y == 0):     #(0,0) is the identity
        return P
    elif P.x == 0 and P.y == 0:
        return Q
    elif Q.x == 0 and Q.y == 0:
        return P
    elif P == Q:                        #in case it is called when double should be
        R = eDouble(P)
    else:
        i = P.y-Q.y
        j = P.x-Q.x
        s = (i * modInv(j, P.c.p) ) % P.c.p
        R.x = ( ( (s**2) - P.x - Q.x) % P.c.p)
        R.y = ( (-P.y + s * (P.x - R.x) ) % P.c.p)
    return R

def eDouble(P):                         #same as eAdd but finds the tangent line
    R = point(0, 0, P.c)
    i = ( (3 * P.x ** 2) + P.c.a)       #the slope equation (i/j)
    j = (2 * P.y)
    s = (i * modInv(j, P.c.p) ) % P.c.p
    R.x = ( (s ** 2) - 2 * P.x) % P.c.p
    R.y = (-P.y + s * (P.x - R.x) ) % P.c.p
    return R

def eMult(P, s):                        #"Double and Add Method" for scalar multiplication
    Q = point(0, 0, P.c)      
    T = point(P.x, P.y, P.c)
    B = bin(s)[2:][::-1]                #uses 0b representation to know when to add
    for i in range( len(B) ):           #1 means add and then double T, 0 means just double T
        if B[i] == '1':
            Q = eAdd(Q, T)
        T = eDouble(T)
    if s < 0:                           #handles if s is negative
        Q.y = -Q.y
    return Q

#start of keygen operations
def curveInput():                       #Creates a curve object with the inputed values and validates that it forms a group
    C = curve(0, 0, 0)
    C.a = int( input("enter the a value for curve:") )
    C.b = int( input("enter the b value for curve:") )
    C.p = int( input("enter the prime p the for the field:") )
    if not C.isGroup():
        C = curve(0, 0, 0)
        print("This is not a valid member of the group.")
        return C
    return C

def pointInput(C):                      #creates a point for the passed through curve   
    P = point(0, 0, C)
    P.x = int( input("enter the x value for point:") )
    P.y = int( input("enter the y value for point:") )
    return P

def pointInputValid(C):                 #creates a point and confirms its valid
    P = point(0, 0, C)
    P.x = int( input("enter the x value for point:") )
    P.y = int( input("enter the y value for point:") )
    if not P.pointValid():
        print("The given point is not valid.")
        return 0
    return P

def keyStart(P,n):
    Q = pointInput(P.c)
    Q = eMult(P,n)
    Q.pointDisplay()
    return Q

def keyGen():                           #todo
    n = int(input("enter secret int n:"))
    P = point(0,0,C)
    P = keyStart(P,n)
    #s = input("Do you have a recived point to enter? (y/n)")    #in practice only the x coord is sent
    #if s == 'n':                                                #there are only to possible y's (y and -y)
    return P
    #Q = point(0,0,C)
    #Q = keyStart(Q,n)
    #Q = eMult(P,n)                     #Only the x value is the key.
    #return Q

def modInv(a, m):                       #modular inverse
    a = a % m; 
    for x in range(1, m) : 
        if ( (a * x) % m == 1) : 
            return x 
    return 1

def eElgamalEncrypt(P, Q):
    print("Enter the message:")
    M = pointInputValid(P.c)
    k = int( input("Choose random element k:") )
    C1 = eMult(P, k)
    C2 = eAdd(M, (eMult(Q, k)))
    CT = [C1, C2]
    print(C1.pointDisplay(), C2.pointDisplay())
    return CT

def eElgamalDecrypt(CT, nA):
    M = eAdd( CT[1], eMult( eMult(CT[0],nA),-1) )
    return M

#below is still todo
def ECDSAkey(G, q, C):
    s = int(input("Input secret signing key 1 < s < q-1: "))
    #while s > (q-1):
    #   print("Error s is greater than or equal to q. Enter a valid s or 0 to cancel. ")
    #    s = int( input("Input secret signing key 1 < s < q-1: ") )
    #    if s == 0:
    #        break
    V = eMult(G, s)
    return V
    
def ECDSAsign(G, d, q, s):
    e = (int (hashlib.blake2b(b'd').hexdigest(),16) )
    eG = eMult(G, e)
    s1 = eG.x % q
    s2 = ( (d + (s * s1) ) * modInv(e, G.c.p) ) % q
    S = [s1, s2]
    return S

def ECDSAver(G, d, q, S, V):
    v1 = (d * modInv(S[1],q) )%q
    v2 = (S[0] * modInv(S[1],q) )%q
    T  = eAdd( eMult(G, v1), eMult(V, v2) )
    I  = T.x % q
    print(I, S[0])
    return I
