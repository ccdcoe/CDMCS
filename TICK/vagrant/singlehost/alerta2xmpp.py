'''
wget https://github.com/abusesa/idiokit/archive/master.tar.gz
tar -xzf master.tar.gz
cd idiokit-master/
python setup.py install

pip install git+https://github.com/ccdcoe/CDMCS.git#subdirectory=TICK/Alerta/alerta2xmpp

export XMPP_USER=blih
export XMPP_MUC=blah

'''



import idiokit
from idiokit.xmpp import connect, jid

import os
import getpass


from alerta.app import app
from alerta.plugins import PluginBase

XMPP_USER = os.environ.get('XMPP_USER') or app.config.get('XMPP_USER', raw_input("XMPP JID: "))
XMPP_PASS = os.environ.get('XMPP_PASS') or app.config.get('XMPP_PASS', getpass.getpass())
XMPP_MUC = os.environ.get('XMPP_MUC') or app.config.get('XMPP_MUC', raw_input("XMPP MUC: "))



@idiokit.stream
def main():
    xmpp = yield connect(XMPP_USER, XMPP_PASS)
    room = yield xmpp.muc.join(XMPP_MUC)

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
