import web
from hmac import hmac_sha1
from Crypto.Random import get_random_bytes
from time import sleep

hmac_key = get_random_bytes(128)

def insecure_compare(data1, data2):
    length = min(len(data1), len(data2))
    #print(f"LENGTH: {length}")
    for i in range(length):
        #print(f"data1[{i}]: {data1[i]} ; data2[{i}]: {data2[i]}")
        if data1[i] == data2[i]:
            sleep(0.05)
        else:
            return False
    if len(data1) != len(data2):
        return False
    return True
    

def fromhex(hexstring):
    if len(hexstring)%2 == 0:
        return bytes.fromhex(hexstring)
    else:
        return bytes.fromhex('0'+hexstring)

render = web.template.render("templates/", globals={'hmac_key':hmac_key, 'hmac_sha1':hmac_sha1, 'insecure_compare': insecure_compare, 'fromhex': fromhex})
urls = (
        '/', 'index',
        '/test', 'test',
        )


class index:
    def GET(self):
        return render.index()

class test:
    def GET(self):
        i = web.input(file=None, signature=None)
        return render.test(i.file, i.signature)


if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
