'''
 wget https://github.com/abusesa/idiokit/archive/master.tar.gz
tar -xzf master.tar.gz
cd idiokit-master/
python setup.py install


'''

import getpass

import idiokit
from idiokit.xmpp import connect, jid


@idiokit.stream
def main():
    xmpp = yield connect(raw_input("Username: "), getpass.getpass())
    room = yield xmpp.muc.join(raw_input("Channel: "))

    while True:
        elements = yield room.next()

        for message in elements.named("message").with_attrs("from"):
            sender = jid.JID(message.get_attr("from"))
            if sender == room.jid:
                continue

            for body in message.children("body"):
                #yield room.send(body)
		        print body


if __name__ == "__main__":
    idiokit.main_loop(main())
