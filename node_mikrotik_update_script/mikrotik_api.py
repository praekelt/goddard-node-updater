import hashlib
import binascii
import select


class MikrotikAPIException(Exception):
    pass


class MikrotikAPI:
    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0

    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login"]):
            chal = binascii.unhexlify((attrs['=ret']).encode('UTF-8'))

        md = hashlib.md5()
        md.update(b'\x00')
        md.update(pwd.encode('UTF-8'))
        md.update(chal)
        output = self.talk(["/login", "=name=" + username, "=response=00" + binascii.hexlify(md.digest()).decode('UTF-8')])
        return output

    def talk(self, words):
        if self.write_sentence(words) == 0: return
        r = []
        while 1:
            i = self.read_sentence();
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j+1:]
            r.append((reply, attrs))
            if reply == '!done': return r

    def write_sentence(self, words):
        ret = 0
        for w in words:
            self.write_word(w)
            ret += 1
        self.write_word('')
        return ret

    def read_sentence(self):
        r = []
        while 1:
            w = self.read_word()
            if w == '': return r
            r.append(w)

    def write_word(self, w):
        self.write_len(len(w))
        self.write_str(w)

    def read_word(self):
        ret = self.read_str(self.read_len())
        return ret

    def write_len(self, l):
        if l < 0x80:
            self.write_str(chr(l))
        elif l < 0x4000:
            l |= 0x8000
            self.write_str(chr((l >> 8) & 0xFF))
            self.write_str(chr(l & 0xFF))
        elif l < 0x200000:
            l |= 0xC00000
            self.write_str(chr((l >> 16) & 0xFF))
            self.write_str(chr((l >> 8) & 0xFF))
            self.write_str(chr(l & 0xFF))
        elif l < 0x10000000:
            l |= 0xE0000000
            self.write_str(chr((l >> 24) & 0xFF))
            self.write_str(chr((l >> 16) & 0xFF))
            self.write_str(chr((l >> 8) & 0xFF))
            self.write_str(chr(l & 0xFF))
        else:
            self.write_str(chr(0xF0))
            self.write_str(chr((l >> 24) & 0xFF))
            self.write_str(chr((l >> 16) & 0xFF))
            self.write_str(chr((l >> 8) & 0xFF))
            self.write_str(chr(l & 0xFF))

    def read_len(self):
        c = ord(self.read_str(1))
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.read_str(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
            c <<= 8
            c += ord(self.read_str(1))
        return c

    def write_str(self, str):
        n = 0;
        while n < len(str):
            r = self.sk.send(bytes(str[n:]))
            if r == 0: raise RuntimeError("Connection closed by remote end")
            n += r

    def read_str(self, length):
        ret = ''
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == '': raise RuntimeError("Connection closed by remote end")
            ret += s.decode('UTF-8', 'replace')
        return ret

    def readall(self, timeout=2):
        out = []
        while True:
            ready = select.select([self.sk], [], [], timeout)

            if ready[0]:
                data = self.read_sentence()

                #print '\nDATA:\n%s\n' % data

                if data[0] == u'!done':
                    break

                elif data[0] == u'!trap':
                    raise MikrotikAPIException('Trapped Exception: %s' % data[1])

                else:
                    out.append(data)

            else:
                # This is triggered the first time we timeout
                break

        return out

    def converse(self, sentence):
        if not isinstance(sentence, list):
            raise Exception('Converse requires sentence as a Python List. You passed %s' % type(sentence))

        self.write_sentence(sentence)
        res = self.readall()
        return res
