'''
wget https://github.com/abusesa/idiokit/archive/master.tar.gz
tar -xzf master.tar.gz
cd idiokit-master/
python setup.py install

pip install git+https://github.com/ccdcoe/CDMCS.git#subdirectory=TICK/Alerta/alerta2xmpp

export XMPP_USER=blih
export XMPP_MUC=blah

'''



import os
import sys
import logging
from logging.handlers import SysLogHandler

import idiokit
from idiokit.xmpp import connect, jid
from idiokit.xmlcore import Element
import getpass

from alerta.app import app
from alerta.plugins import PluginBase

LOG = logging.getLogger('alerta.plugins.logger')

XMPP_USER = os.environ.get('XMPP_USER') or app.config.get('XMPP_USER', raw_input("XMPP JID: "))
XMPP_PASS = os.environ.get('XMPP_PASS') or app.config.get('XMPP_PASS', getpass.getpass())
XMPP_MUC = os.environ.get('XMPP_MUC') or app.config.get('XMPP_MUC', raw_input("XMPP MUC: "))


class XMPP(PluginBase):

    def __init__(self, name=None):

        self.xmpp = yield connect(XMPP_USER, XMPP_PASS)
        self.room = yield xmpp.muc.join(XMPP_MUC)

        super(XMPP, self).__init__(name)

    def pre_receive(self, alert):
        return alert

    def post_receive(self, alert):
        body = Element("body")
        body.text  = "*[%s] %s %s - _%s on %s_* <%s/#/alert/%s|%s>" % (
            alert.status.capitalize(), alert.environment, alert.severity.capitalize(), alert.event, alert.resource, DASHBOARD_URL,
            alert.id, alert.get_id(short=True)
        )
        yield room.send(body)

    def status_change(self, alert, status, text):
        pass
