#!/usr/bin/python2.7

import os
import plistlib

d = { 'ApImg4Ticket':plistlib.Data(open('apticket.der', 'rb').read()),
      'BBTicket':plistlib.Data(open('bbticket.der', 'rb').read()),
    }

print plistlib.writePlistToString(d)
