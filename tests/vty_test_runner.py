#!/usr/bin/env python

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil

# add $top_srcdir/contrib to find ipa.py
sys.path.append(os.path.join(sys.path[0], '..', 'contrib'))

from ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assert_(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assert_(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print >> sys.stderr, "Current directory: %s" % os.getcwd()
            print >> sys.stderr, "Consider setting -b"

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)

class TestVTYMGCP(TestVTYBase):
    def vty_command(self):
        return ["./src/osmo-bsc_mgcp/osmo-bsc_mgcp", "-c",
                "doc/examples/osmo-bsc_mgcp/mgcp.cfg"]

    def vty_app(self):
        return (4243, "./src/osmo-bsc_mgcp/osmo-bsc_mgcp", "OpenBSC MGCP", "mgcp")

    def testForcePtime(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assert_(res.find('  rtp force-ptime 20\r') > 0)
        self.assertEquals(res.find('  no rtp force-ptime\r'), -1)

        self.vty.command("configure terminal")
        self.vty.command("mgcp")
        self.vty.command("no rtp force-ptime")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp force-ptime 20\r'), -1)
        self.assertEquals(res.find('  no rtp force-ptime\r'), -1)

    def testOmitAudio(self):
        self.vty.enable()
        res = self.vty.command("show running-config")
        self.assert_(res.find('  sdp audio-payload send-name\r') > 0)
        self.assertEquals(res.find('  no sdp audio-payload send-name\r'), -1)

        self.vty.command("configure terminal")
        self.vty.command("mgcp")
        self.vty.command("no sdp audio-payload send-name")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp sdp audio-payload send-name\r'), -1)
        self.assert_(res.find('  no sdp audio-payload send-name\r') > 0)

        # TODO: test it for the trunk!

    def testBindAddr(self):
        self.vty.enable()

        self.vty.command("configure terminal")
        self.vty.command("mgcp")

        # enable.. disable bts-bind-ip
        self.vty.command("rtp bts-bind-ip 254.253.252.250")
        res = self.vty.command("show running-config")
        self.assert_(res.find('rtp bts-bind-ip 254.253.252.250') > 0)
        self.vty.command("no rtp bts-bind-ip")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp bts-bind-ip'), -1)

        # enable.. disable net-bind-ip
        self.vty.command("rtp net-bind-ip 254.253.252.250")
        res = self.vty.command("show running-config")
        self.assert_(res.find('rtp net-bind-ip 254.253.252.250') > 0)
        self.vty.command("no rtp net-bind-ip")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find('  rtp net-bind-ip'), -1)


if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print "confpath %s, workdir %s" % (confpath, workdir)
    os.chdir(workdir)
    print "Running tests for specific VTY commands"
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYMGCP))

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
